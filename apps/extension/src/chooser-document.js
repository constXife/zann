// Chrome omits extension-origin frames from webNavigation. The packaged iframe
// reports browser-read-only ancestorOrigins over its own runtime port instead.
export async function identifyChooser(port, expectedOrigin) {
  let timer, receive, disconnected;
  try {
    await new Promise((resolve, reject) => {
      receive = message => {
        if (message.type !== 'ancestry') return;
        if (!Array.isArray(message.origins) || message.origins.length !== 1 || message.origins[0] !== expectedOrigin) reject(new Error('Chooser parent changed.'));
        else resolve();
      };
      disconnected = () => reject(new Error('Chooser disconnected.'));
      port.onMessage.addListener(receive); port.onDisconnect.addListener(disconnected);
      timer = setTimeout(() => reject(new Error('Chooser identification timed out.')), 4500);
      port.postMessage({ type: 'identify' });
    });
  } finally {
    clearTimeout(timer); port.onMessage.removeListener(receive); port.onDisconnect.removeListener(disconnected);
  }
}
