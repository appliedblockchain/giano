import type { EventLog, Log, LogDescription } from 'ethers';
import { ethers } from 'ethers';
import { PassKey__factory } from '../typechain-types';

export const parseLog = (log: Log | EventLog) => {
  const intr = new ethers.Interface(PassKey__factory.abi);
  const topics = [...log.topics];
  const data = log.data;
  return intr.parseLog({ topics, data }) as LogDescription;
};
