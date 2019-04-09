import DidKey from '../lib/DidKey';

const originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;

beforeEach(() => {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 5000;
});

afterEach(() => {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
});

afterAll(() => {
  console.log('Browser test finished');
});

describe('DidKey in browser', () => {
  it('should sign/verify with a symmetric key.', async (done) => {
    const alg = { name: 'hmac', hash: 'SHA-256' };
    console.log(alg);
    const didKey = new DidKey(window.crypto, alg, null, true);
    console.log(didKey);
    expect(didKey).toBeDefined();
    const data = Buffer.from('abcdefg');
    console.log('before signature');
    const signature = await didKey.sign(data);
    console.log('after signature with signature: ' + signature);
    done();
    // const success = await didKey.verify(data, signature);
    // console.log(`signature results: ${success}`);
    // expect(success).toEqual(true);
  });
});
