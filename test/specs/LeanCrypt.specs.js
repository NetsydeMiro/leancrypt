let expect = chai.expect;
import { LeanCrypt } from '../src/LeanCrypt.js';
describe('LeanCrypt', () => {
    describe('#encrypt()', () => {
        it('should encrypt plain text', async () => {
            let leanCrypt = new LeanCrypt();
            let plainText = 'some text';
            let passphrase = 'a passphrase';
            let cipherText = await leanCrypt.encrypt(plainText, passphrase);
            expect(cipherText).to.not.equal(plainText);
        });
        it('encrypting same plain text yields differing cipher text (because of random salt & iv)', async () => {
            let leanCrypt = new LeanCrypt();
            let plainText = 'some text';
            let passphrase = 'a passphrase';
            let cipherText1 = await leanCrypt.encrypt(plainText, passphrase);
            let cipherText2 = await leanCrypt.encrypt(plainText, passphrase);
            expect(cipherText1).to.not.equal(cipherText2);
        });
    });
    describe('#decrypt()', () => {
        it('should decrypt cipher text', async () => {
            let leanCrypt = new LeanCrypt();
            let plainText = 'some text';
            let passphrase = 'a passphrase';
            let cipherText = await leanCrypt.encrypt(plainText, passphrase);
            let decipheredText = await leanCrypt.decrypt(cipherText, passphrase);
            expect(plainText).to.equal(decipheredText);
        });
        it('decrypting cipher texts produced from same plain texts yields same output (because salt & iv are encoded in encrypted result)', async () => {
            let leanCrypt = new LeanCrypt();
            let plainText = 'some text';
            let passphrase = 'a passphrase';
            let cipherText1 = await leanCrypt.encrypt(plainText, passphrase);
            let cipherText2 = await leanCrypt.encrypt(plainText, passphrase);
            let decipheredText1 = await leanCrypt.decrypt(cipherText1, passphrase);
            let decipheredText2 = await leanCrypt.decrypt(cipherText2, passphrase);
            expect(decipheredText1).to.equal(decipheredText2);
        });
    });
});
