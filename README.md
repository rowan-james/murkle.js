# Murkle.js
A small, functional Merkle Tree implementation

```
const tree = MerkleTree.new(['a', 'b', 'c', 'd'])
const proof = MerkleTree.prove(tree, 1)
const isProven = MerkleTree.isProven('b', 1, '58c89d709329eb37285837b042ab6ff72c7c8f74de0446b091b6a0131c102cfd', proof)

console.log(isProven)
> true
```
