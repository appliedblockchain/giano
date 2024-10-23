import React, { useEffect } from 'react';
import {
  Image,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  View
} from 'react-native';

import logo from './assets/logo.png';
import { Btn, Divider, Section } from './components';
import { usePasskey } from './providers/passkey';



function Login(): React.JSX.Element {
  const [username, setUsername] = React.useState<string|null>(null);

  const {
    createUser,
    // isSupported,
    openPasskeyCredential,
    registrationResult,
    passkeys,
  } = usePasskey();




  useEffect(() => {
    const checkSupported = async ()=> {
      try {
        const r = await fetch('https://deadly-possible-spider.ngrok-free.app/.well-known/apple-app-site-association');
        const json = await r.json();
        console.log('json', json);
      } catch (e) {
        console.error('error', e);
      }

    };
    checkSupported();
  },[]);


  return (
    <SafeAreaView style={{flex:1}}>
      <StatusBar />
      <ScrollView
        contentInsetAdjustmentBehavior="automatic"
        contentContainerStyle={{  flexGrow: 1, justifyContent: 'center', padding: 20 }}
        >
        <View >
          <View style={{ alignItems: 'center', gap: 12 }}>
            <Image source={logo} style={{ width: 100, height: 100 }} />
            <Text style={styles.title} >GIANO</Text>
            <Btn title="Login" onPress={openPasskeyCredential} />

          </View>
          <Section><Divider >or</Divider></Section>
          <Section title="Create account">
            <View>
              <TextInput
                autoCapitalize="none"
                placeholder="Passkey *"
                style={styles.input}
                onChangeText={setUsername}
              />
            </View>
            <View>
              <Btn title="Create account" onPress={() => username && createUser(username)} />
            </View>
            <View>
              <Text>Register Result</Text>
              <Text>{JSON.stringify(registrationResult, null, 2)}</Text>
            </View>
          </Section>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  title: {
    alignItems: 'center',
    fontSize: 32,
    fontWeight: 'bold',
  },
  input: {
    height: 40,
    borderRadius: 8,
    backgroundColor: 'rgba(247, 248, 253, 1)',
    padding: 10
  },
});

export default Login;
