const { BN } = require('bn.js')

const toBN = (obj) => {
  if (BN.isBN(obj)) {
    return obj
  }
  if (obj === +obj) {
    return new BN(obj)
  }
  const str = obj + ''
  return str.startsWith('0x') ? new BN(str.substring(2), 16) : new BN(str, 10)
}

module.exports = {
  toBN,
}
