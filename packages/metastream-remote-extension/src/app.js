'use strict'

//
// The app script handles bidirectional communication with the background
// script from the Metastream application.
//
;(function app() {
  const isInstalled = typeof document.documentElement.dataset.extensionInstalled !== 'undefined'
  const METASTREAM_APP_URL = 'https://app.getmetastream.com'
  const isMetastreamUrl = url =>
    url.startsWith(METASTREAM_APP_URL) ||
    url.startsWith('http://local.getmetastream.com') ||
    url.startsWith('http://localhost:8080') ||
    url.startsWith('https://localhost:8080')
  if (isInstalled) {
    console.warn(`Metastream already initialized, is the extension installed twice?`)
    return
  }

  /*if (window.self !== window.top) {
    console.warn('Metastream is unsupported within subframes.')
    return
  }*/
  if (window.parent !== window.self) {
    try {
      let parent = window.parent;  
      do {
        if (isMetastreamUrl(parent.location.href)) {
          console.log('Abandon loading app.js Metastream subframe within Metastream.')
          return
        }
        parent = parent.parent;
      } while (parent != window.top)
    } catch (e) {
    }
  }

  function dispatchInstallEvent() {
    document.dispatchEvent(new Event('metastreamRemoteInstalled'))
  }

  // Notify background script of initialization request
  chrome.runtime.sendMessage({ type: 'metastream-init' }, (initialized) => {
    document.documentElement.dataset.extensionInstalled = ''

    try {
      const manifest = chrome.runtime.getManifest()
      document.documentElement.dataset.extensionId = chrome.runtime.id
      document.documentElement.dataset.extensionVersion = manifest.version
    } catch (e) {}

    if (document.readyState === 'complete') {
      dispatchInstallEvent()
    } else {
      window.addEventListener('load', dispatchInstallEvent, false)
    }

    console.debug(`[Metastream Remote] Initialized`, initialized)
  })

  // Listen for subframe events
  chrome.runtime.onMessage.addListener((message) => {
    if (typeof message !== 'object' || typeof message.type !== 'string') return

    if (message.type.startsWith('metastream-')) {
      console.debug('[Metastream Remote] Received message', message)

      // Send to main world
      message.__internal = true
      window.postMessage(message, location.origin)
    }
  })

  // Listen for events to forward to background script
  window.addEventListener('message', (event) => {
    if (event.origin !== location.origin) return
    const { data: action } = event
    if (typeof action !== 'object' || typeof action.type !== 'string' || action.__internal) return

    if (action.type.startsWith('metastream-')) {
      console.debug('[Metastream Remote] Forwarding message to background', action)
      chrome.runtime.sendMessage(action)
    }
  })
})()
