/// <reference path="../src/LeanCrypt.ts" />

let expect = chai.expect

describe('LeanCrypt', () => {

    describe('#encrypt()', () => {
        it('should encrypt plain text', async () => {
            let plainText = 'some text'
            let passphrase = 'a passphrase'

            let leanKey = await LeanCrypt.newKey(passphrase)

            let cipherText = await LeanCrypt.encrypt(plainText, leanKey.key)

            expect(cipherText).to.not.equal(plainText)
        })
    })

    describe('#decrypt()', () => {
        it('should decrypt cipher text', async () => {
            let plainText = 'some text'
            let passphrase = 'a passphrase'

            let leanKey = await LeanCrypt.newKey(passphrase)

            let cipherText = await LeanCrypt.encrypt(plainText, leanKey.key)

            let decipheredText = await LeanCrypt.decrypt(cipherText, leanKey.key)

            expect(decipheredText).to.equal(plainText)
        })
    })

    describe('#getKey()', () => {
        it('A key can be recreated with same passphrase & salt', async () => {
            let plainText = 'some text'
            let passphrase = 'a passphrase'

            let leanKey1 = await LeanCrypt.newKey(passphrase)
            let cipherText = await LeanCrypt.encrypt(plainText, leanKey1.key)

            let leanKey2 = await LeanCrypt.getKey(passphrase, leanKey1.salt)
            let decipheredText = await LeanCrypt.decrypt(cipherText, leanKey2.key)

            expect(decipheredText).to.equal(plainText)
        })
    })
})