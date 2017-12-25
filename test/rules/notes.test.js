const chai = require('chai')
const targaryen = require('targaryen/plugins/chai')
const expect = chai.expect
const data = require('../../database.example.json')
const rules = require('../../database.rules.json')

chai.use(targaryen)

describe('Notes app security rules', () => {

  before(function() {
    targaryen.setFirebaseData(data)
    targaryen.setFirebaseRules(rules)
  })

  it('should not allow unauthenticated user to read all data', () => {
    expect().cannot.read.path('/')
  })

  it('should not allow authenticated user to read /users', () => {
    let auth = {
      uid: 'user0001'
    }
    expect(auth).cannot.read.path('/users')
  })

  it('should allow authenticated user to read their data', () => {
    let auth = {
      uid: 'user0001'
    }
    expect(auth).can.read.path('/users/user0001')
    expect(auth).can.read.path('/users/user0001/notes')
    expect(auth).can.read.path('/users/user0001/notes/node0001')
  })

  it('should allow authenticated user to write to their data', () => {
    let auth = {
      uid: 'user0001'
    }
    expect(auth).can.write({
      text: 'new note'
    }).to.path('/users/user0001/notes/node0004')
  })

  it('should not allow user0001 to read user0002 data', () => {
    let auth = {
      uid: 'user0001'
    }
    expect(auth).cannot.read.path('/users/user0002')
    expect(auth).cannot.read.path('/users/user0002/notes')
    expect(auth).cannot.read.path('/users/user0002/notes/node0001')
  })

  it('should not allow user0002 to read user0001 data', () => {
    let auth = {
      uid: 'user0002'
    }
    expect(auth).cannot.read.path('/users/user0001')
    expect(auth).cannot.read.path('/users/user0001/notes')
    expect(auth).cannot.read.path('/users/user0001/notes/node0001')
  })

  it('should not allow user0001 to write note to user0002', () => {
    let auth = {
      uid: 'user0001'
    }
    expect(auth).cannot.write({
      text: 'new note'
    }).to.path('/users/user0002/notes/node0004')
  })

  it('should not allow user0002 to write note to user0001', () => {
    let auth = {
      uid: 'user0002'
    }
    expect(auth).cannot.write({
      text: 'new note'
    }).to.path('/users/user0001/notes/node0004')
  })
})
