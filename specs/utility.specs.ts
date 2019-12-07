let expect = chai.expect

import { hash } from '../src/utility.js'

describe('utility', () => {
    describe('hash()', () => {

        it('Hashes the input', async () => { 
            let passphrase = 'a password'

            let hashed = await hash(passphrase)

            expect(hashed.hashString).to.not.equal(passphrase)
            expect(hashed.saltString).to.not.equal(passphrase)
            expect(hashed.hashString).to.not.equal(hashed.saltString)
        })

        it('Hashes inputs to same values when salt provided', async () => { 
            let passphrase = 'a password'
            let salt = 'some salt'

            let hashed1 = await hash(passphrase, salt)
            let hashed2 = await hash(passphrase, salt)

            expect(hashed1.hashString).to.equal(hashed2.hashString)
            expect(hashed1.saltString).to.equal(hashed2.saltString)
        })

        it('Hashes same inputs to different values when salt not provided (since it is randomly generated)', async () => { 
            let passphrase = 'a password'

            let hashed1 = await hash(passphrase)
            let hashed2 = await hash(passphrase)

            expect(hashed1.hashString).to.not.equal(hashed2.hashString)
            expect(hashed1.saltString).to.not.equal(hashed2.saltString)
        })
    })
})