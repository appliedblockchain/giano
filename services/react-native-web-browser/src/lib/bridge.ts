export const bridgeScript = function ({
  bridgeName = 'rnBridge',
  preScript,
  postScript
}: {
  bridgeName?: string,
  preScript?: string,
  postScript?: string
}) {
  return `
  ${preScript}
  ;;
  function getEventData(event) {
    const rawData = event.data || event.nativeEvent.data;
    const data = typeof rawData === 'string' ? JSON.parse(rawData) : rawData;
    return data;
  };
  function Bridge(win) {
    this.window = win;
    const isAndroid = win.navigator.userAgent.includes('Android');
    this.eventEmitter = isAndroid ? win.document : win;
    this.request = (ecoData) => {
      if (!ecoData.id) {
        throw new Error('id is required');
      }
      return new Promise((resolve, reject) => {
        const callback = (event) => {
          const data = getEventData(event);
          if (data.id === ecoData.id) {
            resolve(data); 
            this.eventEmitter.removeEventListener('message', callback);
          } else {
            reject(new Error('id not found, ' + JSON.stringify(data)));
          }
        };
        this.eventEmitter.addEventListener('message', callback);
        this.window.postMessage(JSON.stringify(ecoData));
      })
    }
  };
  window.${bridgeName} = new Bridge(window);
  ${postScript}
  true;
  `;
};
