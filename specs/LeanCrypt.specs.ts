let expect = chai.expect

import { LeanCrypt, LeanKey } from '../src/LeanCrypt.js'

describe('LeanCrypt', () => {

    describe('#encrypt()', () => {
        it('should encrypt plain text', async () => {
            let leanCrypt = new LeanCrypt()

            let plainText = 'some text'
            let passphrase = 'a passphrase'

            let leanKey = await leanCrypt.newKey(passphrase)

            let cipherText = await leanCrypt.encrypt(plainText, leanKey.key)

            expect(cipherText).to.not.equal(plainText)
        })
    })

    describe('#decrypt()', () => {
        it('should decrypt cipher text', async () => {
            let leanCrypt = new LeanCrypt()

            let plainText = 'some text'
            let passphrase = 'a passphrase'

            let leanKey = await leanCrypt.newKey(passphrase)

            let cipherText = await leanCrypt.encrypt(plainText, leanKey.key)

            let decipheredText = await leanCrypt.decrypt(cipherText, leanKey.key)

            expect(decipheredText).to.equal(plainText)
        })
    })

    describe('#getKey()', () => {
        it('A key can be recreated with same passphrase & salt', async () => {
            let leanCrypt = new LeanCrypt()

            let plainText = 'some text'
            let passphrase = 'a passphrase'

            let leanKey1 = await leanCrypt.newKey(passphrase)
            let cipherText = await leanCrypt.encrypt(plainText, leanKey1.key)

            let leanKey2 = await leanCrypt.getKey(passphrase, leanKey1.salt)
            let decipheredText = await leanCrypt.decrypt(cipherText, leanKey2.key)

            expect(decipheredText).to.equal(plainText)
        })
    })
})