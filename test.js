const MerkleTree = require('./')
const tap = require('tap')

tap.test('create tree with sha256', t => {
  const tree = MerkleTree.new(['a', 'b', 'c', 'd'])
  t.test('root hash is 58c89...2cfd', t => {
    t.equal(tree.root.value, '58c89d709329eb37285837b042ab6ff72c7c8f74de0446b091b6a0131c102cfd')
    t.end()
  })

  t.test('can generate proofs', t => {
    const proof = MerkleTree.prove(tree, 1)
    t.strictSame(proof, ["ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    "d3a0f1c792ccf7f1708d5422696263e35755a86917ea76ef9242bd4a8cf4891a"])
    t.end()
  })

  t.test('can confirm proofs', t => {
    const proof = MerkleTree.prove(tree, 1)
    const isProven = MerkleTree.isProven('b', 1, '58c89d709329eb37285837b042ab6ff72c7c8f74de0446b091b6a0131c102cfd', proof)
    t.ok(isProven)
    t.end()
  })
  t.end()
})
