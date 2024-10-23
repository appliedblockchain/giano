/**
 * Sample React Native App
 * https://github.com/facebook/react-native
 *
 * @format
 */

import { install } from 'react-native-quick-crypto';
import 'text-encoding-polyfill';
install();


import React from 'react';

import Login from './Login';
import Wallet from './Wallet';
import { PasskeyProvider, usePasskey } from './providers/passkey';

function App(): React.JSX.Element {
  return <PasskeyProvider>
    <Nav />
  </PasskeyProvider>;
}

function Nav(): React.JSX.Element {
  const { user } = usePasskey();
  console.log('user', user);
  if (user) {
    return <Wallet />;
  }
  return <Login />;
}

export default App;
