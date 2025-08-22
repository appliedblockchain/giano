/* eslint-disable max-lines-per-function */
import Constants from 'expo-constants';
import { useEffect, useRef, useState } from 'react';
import { StyleSheet } from 'react-native';
import { WebView } from 'react-native-webview';

import { bridgeScript } from '@/lib/bridge';


export function Browser({ url }: { url: string }) {
  const webviewRef = useRef<WebView>(null);
  const [isLoaded, setIsLoaded] = useState<boolean | undefined>(undefined);

  useEffect(() => {
    if (isLoaded !== true) return;
    console.log('injectJavaScript');
    webviewRef.current?.injectJavaScript(bridgeScript({
      postScript: `
if (!window.navigator.credentials) {
  window.navigator.credentials = {
    get: (args) => {
      alert('get' + JSON.stringify(args));
      return window.rnBridge.request({
        id: Math.random().toString(36).substring(2, 15),
        type: 'credentialGetRequest'
      }).then((result) => {
        alert('get result' + JSON.stringify(result));
        return result;
      }).catch((error) => {
        alert('get error' + JSON.stringify(error));
        throw error;
      });
    },
    create: (options) => {
      alert('create' + JSON.stringify(options));
      return window.rnBridge.request({
        id: Math.random().toString(36).substring(2, 15),
        type: 'credentialCreateRequest'
      }).then((result) => {
        alert('create result' + JSON.stringify(result));
        return result;
      }).catch((error) => {
        alert('create error' + JSON.stringify(error));
        throw error;
      });
    },
  };
}
`
    }));
    setIsLoaded(true);
  }, [isLoaded]);


  const getEventData = (event: any) => {
    return typeof event.nativeEvent.data === 'string' ? JSON.parse(event.nativeEvent.data) : event.nativeEvent.data;
  }

  const handleMessage = (event: any) => {
    const data = getEventData(event);
    console.log('handleMessage');
    console.log('>>>>>>event', data);
    if (!data.id) return;

    webviewRef.current?.postMessage(JSON.stringify({
      id: data.id,
      type: 'credentialResponse',
      result: {
        id: data.id,
      }
    }));
  };

  const handleLoadEnd = () => {
    console.log('handleLoadEnd');
    setIsLoaded(true);
  };

  return (
    <WebView
      style={styles.container}
      source={{ uri: url }}
      ref={webviewRef}
      onMessage={handleMessage}
      onLoadEnd={handleLoadEnd}

    />
  );
}


const styles = StyleSheet.create({
  container: {
    flex: 1,
    marginTop: Constants.statusBarHeight,
  },
});
