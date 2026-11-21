const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../web/static/js/settings.js'), 'utf8');
function setup(node) {
  const c = vm.createContext({bridgeNodes: [node], bridgeInfo: {profiles: [{tag: 'A', relayed: true}, {tag: 'B', relayed: true}]}, bridgeMark() {}, bridgePreview() {}});
  vm.runInContext(source.slice(source.indexOf('function bridgeTakes'), source.indexOf('function bridgeStatusChip')), c);
  return c;
}
test('cascade: unchecking the last selected connection means none, not all', () => {
  const c = setup({only: ['A']});
  c.bridgeToggleProfile(0, 'A', false);
  assert.equal(c.bridgeNodes[0].selection_mode, 'none');
  assert.equal(c.bridgeTakes(c.bridgeNodes[0], 'A'), false);
  assert.equal(c.bridgeTakes(c.bridgeNodes[0], 'B'), false);
  c.bridgeToggleProfile(0, 'B', true);
  assert.equal(c.bridgeNodes[0].selection_mode, 'selected');
  assert.equal(c.bridgeTakes(c.bridgeNodes[0], 'A'), false);
  assert.equal(c.bridgeTakes(c.bridgeNodes[0], 'B'), true);
});
test('cascade: legacy empty selection and explicit all retain their meaning', () => {
  const c = setup({only: []});
  assert.equal(c.bridgeTakes(c.bridgeNodes[0], 'A'), true);
  c.bridgeToggleProfile(0, 'A', false);
  assert.equal(c.bridgeTakes(c.bridgeNodes[0], 'A'), false);
  c.bridgeToggleProfile(0, 'A', true);
  assert.equal(c.bridgeNodes[0].selection_mode, 'all');
  assert.equal(c.bridgeTakes(c.bridgeNodes[0], 'new connection'), true);
});
