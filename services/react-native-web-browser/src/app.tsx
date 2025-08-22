import { Env } from '@env';
import { View } from 'react-native';

import { Browser } from '@/components/browser';
import { styles } from '@/styles';

export default function App() {
  return (
    <View style={styles.container}>
      <Browser url={Env.API_URL} />
    </View>
  );
}
