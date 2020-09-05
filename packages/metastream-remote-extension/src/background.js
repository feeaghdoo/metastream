'use strict'

//
// The background script provides monitoring of tabs for an active Metastream
// webapp. When activated, web requests originating from the app are modified
// to allow bypassing browser security limitations. This script also provides
// message brokering between embedded websites and the app itself.
//

//=============================================================================
// Locals
//=============================================================================

// Observed tabs on Metastream URL
const watchedTabs = new Set()

// MS tab frames
const watchedTabFrames = {};

// Store for active tabs state
const tabStore = {}

// Used to know which metastream instance to sent browser badge requests to
let lastActiveTabId

// Map from popup webview ID to parent tab ID
// Used for popups pending initialization
const popupParents = {}

// Map from popup tab ID to parent tab ID
// Used for routing messages between popup and parent app
const popupParentTabs = {}

// List of popup tab IDs
const popupTabs = new Set()

//=============================================================================
// Helpers
//=============================================================================

const TOP_FRAME = 0
const HEADER_PREFIX = 'x-metastream'
const METASTREAM_APP_URL = 'https://app.getmetastream.com'
const isMetastreamUrl = url =>
  url.startsWith(METASTREAM_APP_URL) ||
  url.startsWith('http://local.getmetastream.com') ||
  url.startsWith('http://localhost:8080') ||
  url.startsWith('https://localhost:8080')
const isMetastreamFrame = details => details.frameId === watchedTabFrames[details.tabId]
const isValidAction = action => typeof action === 'object' && typeof action.type === 'string'
const isFirefox = () => navigator.userAgent.toLowerCase().includes('firefox')

const asyncTimeout = (promise, timeout = 5000) => {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), timeout))
  ])
}

const escapePattern = pattern => pattern.replace(/[\\^$+?.()|[\]{}]/g, '\\$&')

// Check whether pattern matches.
// https://developer.chrome.com/extensions/match_patterns
const matchesPattern = function(url, pattern) {
  if (pattern === '<all_urls>') return true
  const regexp = new RegExp(
    `^${pattern
      .split('*')
      .map(escapePattern)
      .join('.*')}$`
  )
  return url.match(regexp)
}

// Memoized frame paths
const framePaths = {}

// Get path from top level frame to subframe.
const getFramePath = async (tabId, frameId) => {
  if (framePaths[frameId]) return framePaths[frameId]
  let path = [frameId]
  let currentFrameId = frameId
  while (!isMetastreamFrame({tabId, frameId: currentFrameId}) && currentFrameId > 0) {
    const result = await new Promise(resolve => {
      const details = { tabId, frameId: currentFrameId }
      chrome.webNavigation.getFrame(details, details => {
        if (chrome.runtime.lastError) {
          console.error(`Error in getFramePath: ${chrome.runtime.lastError.message}`)
          resolve()
          return
        }
        resolve(details)
      })
    })
    if (!result) return []
    const { parentFrameId } = result
    path.push(parentFrameId)
    currentFrameId = parentFrameId
  }
  path = path.reverse()
  framePaths[frameId] = path
  return path
}

const sendToFrame = (tabId, frameId, message) =>
  chrome.tabs.sendMessage(tabId, message, { frameId })

const sendToHost = (tabId, message) => sendToFrame(tabId, watchedTabFrames[tabId], message)

const sendWebviewEventToHost = async (tabId, frameId, message) => {
  const framePath = await getFramePath(tabId, frameId)
  sendToHost(
    tabId,
    { type: 'metastream-webview-event', payload: message, framePath }
  )
}

const getLastActiveMetastreamTabId = () => {
  const isMetastreamOpen = watchedTabs.size > 0
  if (!isMetastreamOpen) return -1

  const targetTabId = watchedTabs.has(lastActiveTabId)
    ? lastActiveTabId
    : Array.from(watchedTabs)[0]

  return targetTabId
}

//=============================================================================
// Content scripts
//=============================================================================

const CONTENT_SCRIPTS = [
  {
    matches: ['https://*.netflix.com/*'],
    file: '/scripts/netflix.js'
  },
  {
    matches: ['https://*.hulu.com/*'],
    file: '/scripts/hulu.js'
  },
  {
    matches: ['https://www.dcuniverse.com/*'],
    file: '/scripts/dcuniverse.js'
  },
  {
    matches: ['https://docs.google.com/*', 'https://drive.google.com/*'],
    file: '/scripts/googledrive.js'
  },
  {
    matches: ['https://www.disneyplus.com/*'],
    file: '/scripts/disneyplus.js'
  },
  {
    matches: ['https://*.twitch.tv/*'],
    file: '/scripts/twitch.js'
  }
]

//=============================================================================
// Event listeners
//=============================================================================

// Add Metastream header overwrites
const onBeforeSendHeaders = details => {
  const { tabId, requestHeaders: headers } = details
  const shouldModify = (watchedTabs.has(tabId) && isMetastreamFrame(details)) || tabId === -1
  if (shouldModify) {
    for (let i = headers.length - 1; i >= 0; --i) {
      const header = headers[i].name.toLowerCase()
      if (header.startsWith(HEADER_PREFIX)) {
        const name = header.substr(HEADER_PREFIX.length + 1)
        const value = headers[i].value
        headers.push({ name, value })
        headers.splice(i, 1)
      }
    }
  }
  return { requestHeaders: headers }
}

// Allow embedding any website in Metastream iframe
const onHeadersReceived = details => {
  const { tabId, frameId, responseHeaders: headers } = details
  let permitted = false

  // Whether these headers are within the context of a frame embedded in app.getmetastream.com
  const isMetastreamEmbedFrame = watchedTabs.has(tabId) && !isMetastreamFrame(details)

  const isServiceWorkerRequest = watchedTabs.size > 0 && tabId === -1 && frameId === -1
  const shouldModify = isMetastreamEmbedFrame || isServiceWorkerRequest

  // TODO: HTTP 301 redirects don't get captured. Try https://reddit.com/
  if (shouldModify) {
    for (let i = headers.length - 1; i >= 0; --i) {
      const header = headers[i].name.toLowerCase()
      const value = headers[i].value

      switch (header) {
        case 'x-frame-options':
        case 'frame-options': {
          headers.splice(i, 1)
          permitted = true
          break
        }
        case 'content-security-policy': {
          if (value.includes('frame-ancestors')) {
            const policies = value.split(';').filter(value => !value.includes('frame-ancestors'))

            if (policies.length > 0) {
              headers[i].value = policies.join(';')
            } else {
              // Since Firefox 77, an empty CSP will not overwrite the original
              // Remove it completely if all policies were filtered out
              headers.splice(i, 1)
            }

            permitted = true
          }
          break
        }
        case 'set-cookie': {
          if (isFirefox()) {
            break // only apply SameSite fix in Chrome
          }

          // Allow third-party cookies specifically in Metastream tabs
          if (value.includes('SameSite=')) {
            headers[i].value = value.replace(/SameSite=(Lax|Strict)/i, 'SameSite=None')
          } else {
            // Chrome applies SameSite=Lax by default so avoid this by being explicit
            headers[i].value += '; SameSite=None'
          }

          // SameSite=None requires Secure
          if (!value.includes('Secure')) {
            headers[i].value += '; Secure'
          }

          break
        }
      }
    }
  }

  if (permitted) {
    console.log(`Permitting iframe embedded in tabId=${tabId}, url=${details.url}`)
  }

  return { responseHeaders: headers }
}

const onTabRemove = (tabId, removeInfo) => {
  if (watchedTabs.has(tabId)) {
    stopWatchingTab(tabId)
  }
}

const onBeforeNavigate = details => {
  const { tabId, frameId, url } = details
  if (!watchedTabs.has(tabId)) return
  if (isMetastreamFrame(details)) return
  ;(async () => {
    const framePath = await getFramePath(tabId, frameId)
    const isWebviewFrame = framePath[1] === frameId
    if (isWebviewFrame) {
      fixCookies(details)
      sendWebviewEventToHost(tabId, frameId, { type: 'will-navigate', payload: { url } })
    }
  })()
}

// Programmatically inject content scripts into Metastream subframes
const initScripts = details => {
  const { tabId, frameId, url } = details

  if (url.startsWith('about:blank?webview')) {
    initializeWebview(details)
    return
  }

  if (!watchedTabs.has(tabId)) return

  if (isMetastreamFrame(details) && !popupTabs.has(tabId)) {
    // Listen for top frame navigating away from Metastream
    if (!isMetastreamUrl(details.url)) {
      stopWatchingTab(tabId)
    }
  } else {
    injectContentScripts(details)
  }
}

//Workaround for Chrome 84 change that requires cookies to be SameSite=none; Secure if third party
const fixCookies = details => {
  if (isFirefox()) {
    return
  }
  const { url } = details
  chrome.cookies.getAll({url}, (cookies) => {
    for (let i = 0; i < cookies.length; i++) {
      if (!cookies[i].secure || cookies[i].sameSite !== "no_restriction") {
        cookies[i].secure = true;
        cookies[i].sameSite = "no_restriction";
        chrome.cookies.set({
          url: "https://" + cookies[i].domain.replace(/^\./, '') + cookies[i].path,
          name: cookies[i].name,
          value: cookies[i].value,
          domain: cookies[i].domain,
          path: cookies[i].path,
          secure: true,
          sameSite: "no_restriction",
          expirationDate: cookies[i].expirationDate,
          storeId: cookies[i].storeId,
        });
      }
    }
  })
}

const onCompleted = details => {
  const { tabId, frameId, url } = details
  if (!watchedTabs.has(tabId)) return
  if (isMetastreamFrame(details)) return
  ;(async () => {
    const framePath = await getFramePath(tabId, frameId)
    const isWebviewFrame = framePath[1] === frameId
    if (isWebviewFrame) {
      sendWebviewEventToHost(tabId, frameId, { type: 'did-navigate', payload: { url } })
    }
  })()
}

const onHistoryStateUpdated = details => {
  const { tabId, frameId, url } = details
  if (!watchedTabs.has(tabId)) return
  if (isMetastreamFrame(details)) return
  ;(async () => {
    const framePath = await getFramePath(tabId, frameId)
    const isWebviewFrame = framePath[1] === frameId
    if (isWebviewFrame) {
      sendWebviewEventToHost(tabId, frameId, { type: 'did-navigate-in-page', payload: { url } })
    }
  })()
}

const initializeWebview = details => {
  console.log('Initialize webview', details)
  const { tabId, frameId, url } = details

  const { searchParams } = new URL(url)

  const isPopup = searchParams.get('popup') === 'true'
  const webviewId = searchParams.get('webview')

  let hostId

  if (isPopup) {
    const parentTabId = popupParents[webviewId]
    if (!parentTabId) {
      console.error(`No parent tab ID found for popup webview #${webviewId}`)
      return
    }
    hostId = parentTabId
    popupTabs.add(tabId)
    watchedTabs.add(tabId)
    watchedTabFrames[tabId] = TOP_FRAME
    popupParentTabs[tabId] = hostId
  } else if (watchedTabs.has(tabId)) {
    hostId = tabId
  } else {
    console.warn(`Ignoring webview with tabId=${tabId}, frameId=${frameId}`)
    return
  }

  sendToHost(hostId, { type: `metastream-webview-init${webviewId}`, payload: { tabId, frameId } })

  const tabState = tabStore[hostId]
  const allowScripts = searchParams.get('allowScripts') === 'true'
  if (allowScripts && tabState && !isPopup) {
    tabState.scriptableFrames.add(frameId)
  }
}

// TODO: error injecting scripts into popup windows
const executeScript = (opts, attempt = 0) => {
  chrome.tabs.executeScript(
    opts.tabId,
    {
      file: opts.file,
      runAt: opts.runAt || 'document_start',
      frameId: opts.frameId
    },
    result => {
      if (chrome.runtime.lastError) {
        console.log(`executeScript error [${opts.file}]: ${chrome.runtime.lastError.message}`)
        if (opts.retry !== false) {
          if (attempt < 20) {
            setTimeout(() => executeScript(opts, attempt + 1), 5)
          } else {
            console.error('Reached max attempts while injecting content script.', opts)
          }
        } else {
          console.error('Failed to inject content script', chrome.runtime.lastError, opts)
        }
      } else {
        console.log(`executeScript ${opts.file}`)
      }
    }
  )
}

const injectContentScripts = async details => {
  const { tabId, frameId, url } = details
  if (url === 'about:blank') return

  // Inject common webview script
  executeScript({ tabId, frameId, file: '/webview.js' })

  const framePath = await getFramePath(tabId, frameId)
  const topIFrameId = framePath[1]
  const tabState = tabStore[tabId]
  const scriptable =
    (tabState && tabState.scriptableFrames.has(topIFrameId)) || popupTabs.has(tabId)
  if (scriptable) {
    console.log(`Injecting player script tabId=${tabId}, frameId=${frameId}, url=${url}`)
    executeScript({ tabId, frameId, file: '/player.js' })

    CONTENT_SCRIPTS.forEach(script => {
      if (!script.matches.some(matchesPattern.bind(null, url))) return
      executeScript({ tabId, frameId, file: script.file })
    })
  }
}

//=============================================================================
// Metastream tab management
//=============================================================================

const startWatchingTab = (tab, frameId) => {
  const { id: tabId } = tab
  console.log(`Metastream watching tabId=${tabId} frameId=${frameId}`)
  watchedTabs.add(tabId)
  watchedTabFrames[tabId] = frameId  

  const state = {
    // Webview frames which allow scripts to be injected
    scriptableFrames: new Set(),

    // Event handlers
    onHeadersReceived: onHeadersReceived.bind(null)
  }

  tabStore[tabId] = state

  chrome.webRequest.onHeadersReceived.addListener(
    state.onHeadersReceived,
    {
      tabId,
      urls: ['<all_urls>'],
      types: ['sub_frame', 'xmlhttprequest', 'script']
    },
    [
      chrome.webRequest.OnHeadersReceivedOptions.BLOCKING,
      chrome.webRequest.OnHeadersReceivedOptions.RESPONSEHEADERS, // firefox
      chrome.webRequest.OnHeadersReceivedOptions.RESPONSE_HEADERS, // chromium
      chrome.webRequest.OnHeadersReceivedOptions.EXTRAHEADERS, // firefox
      chrome.webRequest.OnHeadersReceivedOptions.EXTRA_HEADERS // chromium
    ].filter(Boolean)
  )

  const shouldAddGlobalListeners = watchedTabs.size === 1
  if (shouldAddGlobalListeners) {
    chrome.webNavigation.onBeforeNavigate.addListener(onBeforeNavigate)
    if (isFirefox()) {
      chrome.webNavigation.onDOMContentLoaded.addListener(initScripts)
    } else {
      chrome.webNavigation.onCommitted.addListener(initScripts)
    }
    chrome.webNavigation.onCompleted.addListener(onCompleted)
    chrome.webNavigation.onHistoryStateUpdated.addListener(onHistoryStateUpdated)
    chrome.tabs.onRemoved.addListener(onTabRemove)

    // Listen for requests from background script
    chrome.webRequest.onBeforeSendHeaders.addListener(
      onBeforeSendHeaders,
      { tabId: -1, urls: ['<all_urls>'] },
      [
        chrome.webRequest.OnBeforeSendHeadersOptions.BLOCKING,
        chrome.webRequest.OnBeforeSendHeadersOptions.REQUESTHEADERS, // firefox
        chrome.webRequest.OnBeforeSendHeadersOptions.REQUEST_HEADERS, // chromium
        chrome.webRequest.OnBeforeSendHeadersOptions.EXTRA_HEADERS // chromium
      ].filter(Boolean)
    )
  }
}

const stopWatchingTab = tabId => {
  watchedTabs.delete(tabId)
  delete watchedTabFrames[tabId]

  const state = tabStore[tabId]
  if (state) {
    chrome.webRequest.onHeadersReceived.removeListener(state.onHeadersReceived)
    delete tabStore[tabId]
  }

  const shouldRemoveGlobalListeners = watchedTabs.size === 0
  if (shouldRemoveGlobalListeners) {
    chrome.webNavigation.onBeforeNavigate.removeListener(onBeforeNavigate)
    if (isFirefox()) {
      chrome.webNavigation.onDOMContentLoaded.removeListener(initScripts)
    } else {
      chrome.webNavigation.onCommitted.removeListener(initScripts)
    }
    chrome.webNavigation.onCompleted.removeListener(onCompleted)
    chrome.webNavigation.onHistoryStateUpdated.removeListener(onHistoryStateUpdated)
    chrome.tabs.onRemoved.removeListener(onTabRemove)
    chrome.webRequest.onBeforeSendHeaders.removeListener(onBeforeSendHeaders)
  }

  console.log(`Metastream stopped watching tabId=${tabId}`)
}


const PERMISSION_ACTIONS = {
  allowPopups(request) {
    // Allow Metastream to open two popups at the same time without one getting blocked.
    // Some websites can't be played while embedded in the site so they need to open
    // in a popup to have a top-level browser context.
    chrome.contentSettings.popups.set({
      primaryPattern: request.origins[0],
      setting: chrome.contentSettings.PopupsContentSetting.ALLOW
    })
  }
}

const requestPermissions = request => {
  const { action, ...rest } = request
  chrome.permissions.request(rest, granted => {
    if (granted && typeof action === 'string') {
      PERMISSION_ACTIONS[action](request)
    }
  })
}

//=============================================================================
// Background fetch proxy
//=============================================================================

const serializeResponse = async response => {
  let body
  let headers = {}

  const contentType = (response.headers.get('content-type') || '').toLowerCase()
  if (contentType && contentType.indexOf('application/json') !== -1) {
    try {
      body = await response.json()
    } catch (e) {}
  } else {
    body = await response.text()
  }

  for (let pair of response.headers.entries()) {
    headers[pair[0]] = pair[1]
  }

  return {
    ...response,
    headers,
    body
  }
}

// Fetch on behalf of Metastream app, skips cross-domain security restrictions
const request = async (tabId, requestId, url, options) => {
  const { timeout } = options || {}
  const controller = new AbortController()
  const { signal } = controller

  let response, err

  try {
    console.debug(`Requesting ${url}`)
    response = await asyncTimeout(fetch(url, { ...options, signal }), timeout)
  } catch (e) {
    controller.abort()
    err = e.message
  }

  const action = {
    type: `metastream-fetch-response${requestId}`,
    payload: {
      err,
      resp: response ? await serializeResponse(response) : null
    }
  }
  sendToHost(tabId, action)
}

//=============================================================================
// Message passing interface
//=============================================================================

const handleWebviewEvent = async (sender, action) => {
  const { frameId } = sender
  const { id: tabId } = sender.tab

  // popups always send webview events back to host app
  if (popupTabs.has(tabId)) {
    const parentId = popupParentTabs[tabId]
    sendWebviewEventToHost(parentId, watchedTabFrames[tabId], action.payload)
    return
  }

  if (isMetastreamFrame({frameId, tabId})) {
    // sent from app
    sendToFrame(action.tabId || tabId, action.frameId, action.payload)
  } else {
    // sent from embedded frame
    sendWebviewEventToHost(tabId, frameId, action.payload)
  }
}

function messageHandler(action, sender, sendResponse) {
  const { id: tabId } = sender.tab
  if (!isValidAction(action)) return

  // Listen for Metastream app initialization signal
  if (action.type === 'metastream-init' && isMetastreamUrl(sender.url)) {
    startWatchingTab(sender.tab, sender.frameId)
    sendResponse(true)
    return
  }

  // Filter out messages from non-Metastream app tabs
  if (!watchedTabs.has(tabId)) return

  switch (action.type) {
    case 'metastream-webview-event':
      handleWebviewEvent(sender, action)
      break
    case 'metastream-fetch': {
      const { requestId, url, options } = action.payload
      request(tabId, requestId, url, options)
      break
    }
    case 'metastream-popup-init': {
      const { id: webviewId } = action.payload
      popupParents[webviewId] = tabId
      break
    }
    case 'metastream-focus': {
      const targetTabId = getLastActiveMetastreamTabId()
      if (targetTabId > -1) {
        // window.focus() is not reliable, but the WebExtensions API is!
        chrome.tabs.update(targetTabId, { active: true })
        chrome.tabs.get(targetTabId, tab => {
          chrome.windows.update(tab.windowId, { focused: true })
        })
      }
      break
    }
    case 'metastream-permissions-request': {
      requestPermissions(action.payload)
      break
    }
  }

  if (!popupTabs.has(tabId)) {
    lastActiveTabId = tabId
  }
}

chrome.runtime.onMessage.addListener(messageHandler)

if (chrome.runtime.onMessageExternal) {
  chrome.runtime.onMessageExternal.addListener(messageHandler)
}

//=============================================================================
// Inject content scripts into existing tabs on startup
//=============================================================================

const { content_scripts: contentScripts = [] } = chrome.runtime.getManifest()
const appContentScript = contentScripts.find(
  script => script.js && script.js.some(file => file.endsWith('app.js'))
)

if (appContentScript) {
  chrome.tabs.query({ url: appContentScript.matches }, tabs => {
    tabs.forEach(tab => {
      chrome.tabs.executeScript(tab.id, { file: appContentScript.js[0] })
    })
  })
}

//=============================================================================
// Add URL to session on badge click
//=============================================================================

const getMediaTimeInTab = tabId =>
  new Promise(resolve => {
    chrome.tabs.executeScript(
      tabId,
      {
        file: '/get-media-time.js',
        allFrames: true
      },
      results => {
        let time = (results.length > 0 && !isNaN(results[0]) && results[0]) || undefined
        resolve(time)
      }
    )
  })

// pause media in all non-metastream tabs
const pauseMediaInOtherTabs = () => {
  chrome.tabs.query({ audible: true }, tabs => {
    tabs.forEach(({ id: tabId }) => {
      if (watchedTabs.has(tabId)) return
      chrome.tabs.executeScript(tabId, {
        file: '/pause-media.js',
        allFrames: true
      })
    })
  })
}

const openLinkInMetastream = details => {
  const { url: requestUrl, currentTime, source } = details

  const { protocol } = new URL(requestUrl)
  if (protocol !== 'http:' && protocol !== 'https:') return

  console.log(`Opening URL in Metastream: ${requestUrl}${currentTime ? ` @ ${currentTime}` : ''}`)

  const targetTabId = getLastActiveMetastreamTabId()
  if (targetTabId > -1) {
    sendToHost(targetTabId, {
      type: 'metastream-extension-request',
      payload: { url: requestUrl, time: currentTime, source }
    })
    chrome.tabs.update(targetTabId, { active: true }) // focus tab
  } else {
    const params = new URLSearchParams()
    params.append('url', requestUrl)
    if (currentTime) params.append('t', currentTime)
    if (source) params.append('source', source)
    const url = `${METASTREAM_APP_URL}/?${params.toString()}`
    // const url = `http://localhost:8080/#?${params.toString()}` // dev
    chrome.tabs.create({ url })
  }

  pauseMediaInOtherTabs()
}

const openTabInMetastream = async ({ tab, source }) => {
  const { id: tabId, url } = tab
  if (tabId < 0) return

  // ignore badge presses from Metastream tabs
  if (watchedTabs.has(tabId)) return

  const currentTime = await getMediaTimeInTab(tabId)
  openLinkInMetastream({ url, currentTime, source })
}

chrome.browserAction.onClicked.addListener(tab =>
  openTabInMetastream({ tab, source: 'browser-action' })
)

//=============================================================================
// Create context menu items to add links to metastream session
//=============================================================================

const TARGET_URL_PATTERNS = ['https://*/*']

chrome.contextMenus.create({
  title: 'Open link in Metastream session',
  contexts: ['link'],
  targetUrlPatterns: TARGET_URL_PATTERNS,
  onclick(info, tab) {
    const { linkUrl: url } = info
    if (url) openLinkInMetastream({ url, source: 'context-menu-link' })
  }
})

chrome.contextMenus.create({
  title: 'Open link in Metastream session',
  contexts: ['browser_action'],
  documentUrlPatterns: TARGET_URL_PATTERNS,
  onclick(info, tab) {
    openTabInMetastream({ tab, source: 'context-menu-browser-action' })
  }
})

chrome.contextMenus.create({
  title: 'Open video in Metastream session',
  contexts: ['video'],
  targetUrlPatterns: TARGET_URL_PATTERNS,
  onclick(info, tab) {
    const { srcUrl: url } = info
    if (url) openLinkInMetastream({ url, source: 'context-menu-video' })
  }
})
