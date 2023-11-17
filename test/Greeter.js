import { expect } from 'chai';

describe('Greeter', () => {
  it('should work', async () => {
    const Greeter = await ethers.getContractFactory('Greeter');
    const greeter = await Greeter.deploy('Hello!');

    expect(await greeter.greet()).to.equal('Hello!');

    const setGreetingTx = await greeter.setGreeting('Hola!');
    await setGreetingTx.wait();

    expect(await greeter.greet()).to.equal('Hola!');

    const [, addr1] = await ethers.getSigners();
    await greeter.connect(addr1).setGreeting('Ciao!');

    expect(await greeter.greet()).to.equal('Ciao!');
  });
});
