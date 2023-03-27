const crypto = require('crypto')

// Helper functions
const tco = function (f) {
    while (f && f instanceof Function) {
        f = f.apply(f.context, f.args)
    }
    return f
}

const reverse = s => s.slice().reverse()
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex')
const isEmpty = arr => !arr.length
const isFloat = n => Math.ceil(n) === Math.floor(n)
const isPowerOfN = (n, x) => isFloat(Math.log2(x) / Math.log2(n))
const pad = (bin, width) => bin.length < width ? '0'.repeat(width - bin.length) + bin : bin
const binarize = (index, height) => pad(index.toString(2), height).slice(-height)
const splitIntoIntegers = n => n.split('').map(x => parseInt(x, 10))

const chunk = (arr, n) => {
  const recur = (arr, chunks = []) => {
    if (isEmpty(arr)) return chunks
    const chunk = [arr.slice(0, n)]
    return recur.bind(null, arr.slice(n), chunks.concat(chunk))
  }

  return tco(recur.bind(null, arr))
}

// Construct our Merkle tree
const build = (blocks, hashFn, numberOfChildren) => {
  const leaves = blocks.map(block => ({
    value: hashFn(block),
    children: [],
    height: 0
  }))

  const recur = (nodes, height = 1) => {
    if (nodes.length === 1) return nodes[0]
    const chunks = chunk(nodes, numberOfChildren)
    const parents = chunks.map(children => {
      const values = children.reduce((acc, { value }) => acc + value, '')
      return { children, height, value: hashFn(values) }
    })

    return recur.bind(null, parents, height + 1)
  }

  return tco(recur.bind(null, leaves))
}

// Generate hashes along a specified path
const provePath = (node, binary) => {
  const recur = ({ children }, [ head, ...tail ], acc = []) => {
    const [child, { value }] = head ? children.slice().reverse() : children
    const res = [ value, ...acc ]
    return !isEmpty(tail) ? recur.bind(null, child, tail, res) : res
  }

  return tco(recur.bind(null, node, splitIntoIntegers(binary)))
}

const hashProof = (block, binary, proof, hashFn) => {
  const recur = (path, proof, acc = '') => {
    if (isEmpty(path) && isEmpty(proof)) return acc
    const [pathHead, ...pathTail] = path
    const [proofHead, ...proofTail] = proof
    const accumulator = pathHead ? hashFn(proofHead + acc) : hashFn(acc + proofHead)
    return recur.bind(null, pathTail, proofTail, accumulator)
  }

  const binaryArray = splitIntoIntegers(binary)
  return tco(recur.bind(null, reverse(binaryArray), proof, hashFn(block)))
}

/**
 * @namespace MerkleTree
 */
module.exports = {
  /*
   * @desc Merkle Tree constructor
   * @param {string[]} blocks - Strings representing the unhashed leaves of the tree
   * @param {Object} options
   * @param {Function} options.hashFunction - The hashing function to use for leaves and nodes
   * @param {number} options.numberOfChildren - How many children per node
   * @example
   * const tree = MerkleTree.new(['a', 'b', 'c', 'd'])
   * > { blocks: [ 'a', 'b', 'c', 'd' ],
  hashFunction: [Function: sha256],
  root:
   { children:
      [ { children:
           [ { value:
                'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
               children: [],
               height: 0 },
             { value:
                '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
               children: [],
               height: 0 } ],
          height: 1,
          value:
           '62af5c3cb8da3e4f25061e829ebeea5c7513c54949115b1acc225930a90154da' },
        { children:
           [ { value:
                '2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6',
               children: [],
               height: 0 },
             { value:
                '18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4',
               children: [],
               height: 0 } ],
          height: 1,
          value:
           'd3a0f1c792ccf7f1708d5422696263e35755a86917ea76ef9242bd4a8cf4891a' } ],
     height: 2,
     value:
      '58c89d709329eb37285837b042ab6ff72c7c8f74de0446b091b6a0131c102cfd' } }
   */
  new: (blocks = [], { hashFunction = sha256, numberOfChildren = 2 } = {}) => {
    if (!isPowerOfN(numberOfChildren, blocks.length)) throw new Error(`numberofChildren must be 2^N (received ${numberOfChildren})`)
    const root = build(blocks, hashFunction, numberOfChildren)
    return { blocks, hashFunction, root }
  },
  /**
   * prove
   * @desc Generate proof for a block at a specific index
   * @param {Object} tree - An instance of a Merkle tree
   * @param {number} index - Target leaf index in the leaf array
   * @example
   * const tree = MerkleTree.new(['a', 'b', 'c', 'd'])
   * MerkleTree.prove(tree, 1) // Targeting index 1 for 'b'
   * > ["d3a0f1c792ccf7f1708d5422696263e35755a86917ea76ef9242bd4a8cf4891a",
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"]
   */
  prove: ({ root }, index) => provePath(root, binarize(index, root.height)),
  /**
   * isProven
   * @desc Verify proof for a block at a specific index
   * @param {string} block - Target block
   * @param {number} index - Target index
   * @param {string} rootHash - The Merkle tree root hash
   * @param {string[]} proof - The array of proofs to verify
   * @param {Object} options
   * @param {Function} options.hashFunction - The hashing algorithm to use for verification
   * @example
   * const tree = MerkleTree.new(['a', 'b', 'c', 'd'])
   * const proof = MerkleTree.prove(tree, 1) // Targeting index 1 for 'b'
   * console.log(MerkleTree.isProven('b', 1, '58c89d709329eb37285837b042ab6ff72c7c8f74de0446b091b6a0131c102cfd', proof))
   * > true
   */
  isProven: (block, index, rootHash, proof = [], { hashFunction = sha256 } = {}) => {
    const height = proof.length
    const hash = hashProof(block, binarize(index, height), proof, hashFunction)
    return rootHash === hash
  }
}
