import type { EventLog, Log, LogDescription } from 'ethers';
import { ethers } from 'ethers';
import { Passkey__factory } from '../typechain-types';

export const parseLog = (log: Log | EventLog) => {
  const intr = new ethers.Interface(Passkey__factory.abi);
  const topics = [...log.topics];
  const data = log.data;
  return intr.parseLog({ topics, data }) as LogDescription;
};
