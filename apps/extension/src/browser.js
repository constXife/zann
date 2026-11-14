import { pageFields } from './fields.js';

// UI-facing page failures retain their original cause for diagnostics.
export class PageError extends Error {
  constructor(message, options) { super(message, options); this.name = 'PageError'; }
}

// URLs/document identity come exclusively from privileged browser APIs.
export class BrowserPage {
  constructor(chrome, checkedContext, tabId) { this.chrome = chrome; this.checkedContext = checkedContext; this.tabId = tabId; }
  async frames() {
    const tab = this.tabId === undefined ? (await this.chrome.tabs.query({ active: true, currentWindow: true }))[0] : await this.chrome.tabs.get(this.tabId);
    if (!Number.isInteger(tab?.id)) throw new PageError('Open a secure website to find and fill your logins.');
    if (this.tabId !== undefined && !tab.active) throw new Error('Website is not active.');
    const frames = await this.chrome.webNavigation.getAllFrames({ tabId: tab.id });
    const top = frames?.find(frame => frame.frameId === 0);
    if (!top?.documentId || top.errorOccurred) throw new PageError('This page hasn’t loaded. Open a working sign-in page, then try again.');
    // Admission stays in Rust. An ineligible frame is shown as unavailable when selected.
    return { tabId: tab.id, top, frames: frames.filter(frame => frame.documentId) };
  }
  select(snapshot, frameId) {
    const frame = snapshot.frames.find(frame => frame.frameId === frameId);
    if (!frame) throw new Error('Frame unavailable. Refresh the page selection.');
    let context;
    try { context = JSON.parse(this.checkedContext(snapshot.top.url, frame.url)); }
    catch (cause) { throw new PageError('Choose a sign-in page on the same HTTPS website. Browser pages and other websites cannot be filled here.', { cause }); }
    return { tabId: snapshot.tabId, top: snapshot.top, frame, context };
  }
  async assertCurrent(target) {
    const current = await this.frames();
    const frame = current.frames.find(frame => frame.frameId === target.frame.frameId);
    if (current.tabId !== target.tabId || current.top.documentId !== target.top.documentId ||
        current.top.url !== target.top.url || frame?.documentId !== target.frame.documentId || frame.url !== target.frame.url) {
      throw new PageError('Page changed. Refresh before continuing.');
    }
  }
  watch(target, invalidate) {
    const navigations = [this.chrome.webNavigation.onBeforeNavigate, this.chrome.webNavigation.onCommitted,
      this.chrome.webNavigation.onHistoryStateUpdated, this.chrome.webNavigation.onReferenceFragmentUpdated];
    const changed = details => {
      if (details.tabId === target.tabId && (details.frameId === 0 || details.frameId === target.frame.frameId)) invalidate();
    };
    const removed = tabId => { if (tabId === target.tabId) invalidate(); };
    for (const event of navigations) event.addListener(changed);
    this.chrome.tabs.onRemoved.addListener(removed);
    return () => {
      for (const event of navigations) event.removeListener(changed);
      this.chrome.tabs.onRemoved.removeListener(removed);
    };
  }
  async fields(target, operation, args = {}) {
    await this.assertCurrent(target);
    let results;
    try { results = await this.chrome.scripting.executeScript({
      target: { tabId: target.tabId, documentIds: [target.frame.documentId] },
      world: 'ISOLATED',
      func: pageFields,
      args: [{ operation, topURL: target.top.url, frameURL: target.frame.url, ...args }]
    }); } catch (cause) { throw new PageError('This page can’t be filled. Open a working sign-in page, then try again.', { cause }); }
    const result = results.find(result => result.documentId === target.frame.documentId)?.result;
    if (!result?.ok) throw new PageError(result?.error ?? 'The sign-in form is unavailable. Refresh the page and try again.');
    return result;
  }
}
