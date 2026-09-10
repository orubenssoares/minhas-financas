// Lightweight regression test for the money-calculation logic in public/index.html.
// No framework/build step in this project, so this extracts the inline <script> the
// same way the browser runs it, stubs the DOM/network it touches at load time, and
// asserts against fixture data. Run with `npm test`.
//
// This exists because of a real incident: the dashboard's "Previsão dos próximos
// meses" once computed the current month purely from recurring bill projections,
// ignoring actual transactions — producing a negative forecast while the Transações
// tab showed a different, positive number for the same month. These assertions pin
// down the fixed behavior so that regression can't silently come back.
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
const scriptMatch = html.match(/<script>([\s\S]*)<\/script>\s*<\/body>/);
assert(scriptMatch, 'could not find the app <script> block in public/index.html');
const js = scriptMatch[1];

global.pdfjsLib = { GlobalWorkerOptions: {} };
global.document = {
  getElementById: () => ({ addEventListener(){}, classList:{ toggle(){}, add(){}, remove(){} }, textContent:'', value:'', style:{} }),
  querySelector: () => null,
  createElement: () => ({ click(){}, remove(){}, style:{} }),
  body: { classList: { toggle(){}, add(){}, remove(){} }, appendChild(){} },
};
global.localStorage = { getItem: () => null, removeItem(){}, setItem(){} };
global.fetch = () => Promise.reject(new Error('no network in test sandbox'));
global.window = global;
global.navigator = { clipboard: { writeText(){} } };

const moduleObj = { exports: {} };
const load = new Function('module', 'exports', js + `
;module.exports = {
  monthsOutlook, fixedVariableSplit, generateInsights, txInMonth, state,
  get curYear(){ return curYear }, get curMonth(){ return curMonth },
};`);
load(moduleObj, moduleObj.exports);
const { monthsOutlook, fixedVariableSplit, generateInsights, state, curYear, curMonth } = moduleObj.exports;

assert.strictEqual(curYear, 2026, 'sanity check: system clock is not where the fixtures assume — update the fixture dates');
assert.strictEqual(curMonth, 9, 'sanity check: system clock is not where the fixtures assume — update the fixture dates');

let passed = 0;
function check(name, fn) {
  fn();
  passed++;
  console.log(`  ok — ${name}`);
}

console.log('dashboard-logic.test.js');

// ── Fixture: a recurring bill series last seen two months ago (would get rolled
// forward every month by a naive projection), real transactions for the current
// month, and one pending bill due this month.
state.recurringBills = [
  { id: 'b2', type: 'bill', description: 'Financiamento Carro', amount: 2500, dueDate: '2026-07-15', category: 'Transporte', status: 'done', isRecurring: true, memberId: 'm1' },
];
state.allBills = [
  { id: 'b1', type: 'bill', description: 'Cartão de crédito', amount: 500, dueDate: '2026-09-20', category: 'Outros', status: 'pending', isRecurring: false, memberId: 'm1' },
  { id: 'b2', type: 'bill', description: 'Financiamento Carro', amount: 2500, dueDate: '2026-07-15', category: 'Transporte', status: 'done', isRecurring: true, memberId: 'm1' },
  { id: 'b3', type: 'bill', description: 'IPVA', amount: 900, dueDate: '2026-10-15', category: 'Outros', status: 'pending', isRecurring: false, memberId: 'm1' },
];
state.currentMonthTx = [
  { id: 't1', type: 'income', description: 'Salário', amount: 6000, category: 'Outros', date: '2026-09-05', isFixed: true },
  { id: 't2', type: 'expense', description: 'Aluguel', amount: 1200, category: 'Moradia', date: '2026-09-01', isFixed: true },
  { id: 't3', type: 'expense', description: 'Mercado', amount: 800, category: 'Alimentação', date: '2026-09-03', isFixed: false },
];
state.transactions = state.currentMonthTx;
state.bills = state.allBills.filter(b => b.dueDate.startsWith('2026-09'));

check('current month uses real data, not the recurring projection', () => {
  const [thisMonth] = monthsOutlook(1);
  assert.strictEqual(thisMonth.real, true);
  // income 6000, expense (1200+800) + pending bill (500) = 2500 -> saldo 3500
  assert.strictEqual(thisMonth.toReceive, 6000);
  assert.strictEqual(thisMonth.toPay, 2500);
  assert.strictEqual(thisMonth.saldo, 3500);
  // the old bug: a lone recurring bill projected to -2500 for this exact month
  assert.notStrictEqual(thisMonth.saldo, -2500);
});

check('future months project from recurring series + one-off scheduled bills', () => {
  const [, october] = monthsOutlook(2);
  assert.strictEqual(october.real, false);
  // recurring Financiamento Carro (2500) + one-off IPVA (900) both fall in October
  assert.strictEqual(october.toPay, 3400);
  assert.strictEqual(october.toReceive, 0);
});

check('fixedVariableSplit separates fixed vs. variable real spending', () => {
  const { fixed, variable } = fixedVariableSplit(2026, 9);
  // Aluguel is a fixed expense transaction.
  assert.strictEqual(fixed.length, 1);
  assert.strictEqual(fixed[0].description, 'Aluguel');
  // Mercado (variable expense tx) + Cartão de crédito (pending, non-recurring bill)
  // both belong in "variável".
  assert.strictEqual(variable.length, 2);
  assert.deepStrictEqual(variable.map(v => v.description).sort(), ['Cartão de crédito', 'Mercado']);
});

check('generateInsights flags an over-limit category with a jump-to-Transações action', () => {
  state.categories = [{ id: 'c1', name: 'Alimentação', limit: 100, color: '#f97316' }];
  const insights = generateInsights(state.currentMonthTx);
  const overLimit = insights.find(i => i.text.includes('Alimentação') && i.level === 'error');
  assert(overLimit, 'expected an over-limit insight for Alimentação (800 spent, limit 100)');
  assert.deepStrictEqual(overLimit.action, { tab: 'transacoes', filter: 'Alimentação' });
});

console.log(`\n${passed} passed`);
