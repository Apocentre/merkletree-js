import {SHA3} from 'sha3'
import invariant from 'tiny-invariant'

const EMPTY = Buffer.from([])

const getPairElement = (idx, layer) => {
  const pairIdx = idx % 2 === 0 ? idx + 1 : idx - 1

  if (pairIdx < layer.length) {
    const pairEl = layer[pairIdx]
    invariant(pairEl, 'pairEl')
    return pairEl
  } else {
    return null
  }
}

const bufDedup = (elements) => {
  return elements.filter((el, idx) => {
    return idx === 0 || !elements[idx - 1]?.equals(el)
  })
}

const bufArrToHexArr = (arr) => {
  if (arr.some((el) => !Buffer.isBuffer(el))) {
    throw new Error('Array is not an array of buffers')
  }

  return arr.map((el) => '0x' + el.toString('hex'))
}

const sortAndConcat = (...args) => {
  return Buffer.concat([...args].sort(Buffer.compare.bind(null)))
}

export default class MerkleTree {
  constructor(elements) {
    const original_elements = [...elements]

    if (original_elements.length % 2 === 1) {
      original_elements.push(EMPTY)
    }

    this._elements = original_elements

    this._bufferElementPositionIndex = this._elements.reduce((memo, el, index) => {
      memo[el.toString('hex')] = index
      return memo
    }, {})

    // Create layers
    this._layers = this.getLayers(this._elements)
  }

  getLayers(elements) {
    if (elements.length === 0) {
      throw new Error('empty tree')
    }

    const layers = []
    layers.push(elements)

    // Get next layer until we reach the root
    while ((layers[layers.length - 1]?.length ?? 0) > 1) {
      const nextLayerIndex = layers[layers.length - 1]
      invariant(nextLayerIndex, 'nextLayerIndex')
      layers.push(this.getNextLayer(nextLayerIndex))
    }

    return layers
  }

  getNextLayer(elements) {
    if (elements.length % 2 === 1) {
      elements.push(EMPTY)
    }

    return elements.reduce((layer, el, idx, arr) => {
      if (idx % 2 === 0) {
        // Hash the current element with its pair element
        const pairEl = arr[idx + 1]
        layer.push(MerkleTree.combinedHash(el, pairEl))
      }

      return layer
    }, [])
  }

  static combinedHash(first, second) {
    const sha256 = new SHA3(256)

    if (!first) {
      invariant(second, 'second element of pair must exist')
      return sha256.update(second).digest()
    }
    if (!second) {
      invariant(first, 'first element of pair must exist')
      return sha256.update(first).digest()
    }

    return sha256.update(sortAndConcat(first, second)).digest()
  }

  getRoot() {
    const root = this._layers[this._layers.length - 1]?.[0]
    invariant(root, 'root')
    return root
  }

  getHexRoot() {
    return this.getRoot().toString('hex')
  }

  getProof(el) {
    const initialIdx = this._bufferElementPositionIndex[el.toString('hex')]

    if (typeof initialIdx !== 'number') {
      throw new Error('Element does not exist in Merkle tree')
    }

    const result = []
    let idx = initialIdx
    let current_layer = this._elements

    while (current_layer.length > 1) {
      const pairElement = getPairElement(idx, current_layer)

      if (pairElement) {
        result.push(pairElement)
      } else {
        result.push(Buffer.from([]))
      }

      idx = Math.floor(idx / 2)
      current_layer = this.getNextLayer(current_layer)
    }

    return result
  }

  getHexProof(el) {
    const proof = this.getProof(el)

    return bufArrToHexArr(proof)
  }

  verify(proof, leaf) {
    let computedHash = leaf

    for (let i = 0; i < proof.length; i++) {
      const element = proof[i];
      
      if(computedHash <= element) {
        computedHash = MerkleTree.combinedHash(computedHash, element)
      }
      else {
        computedHash = MerkleTree.combinedHash(element, computedHash)
      }
    }

    return computedHash.equals(this.getRoot())
  }
}
