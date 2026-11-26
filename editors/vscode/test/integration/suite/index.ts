import * as path from 'node:path';
import * as fs from 'node:fs';
import Mocha from 'mocha';

export function run(): Promise<void> {
  const mocha = new Mocha({ timeout: 180000, color: false });
  for (const f of fs.readdirSync(__dirname)) if (f.endsWith('.itest.js')) mocha.addFile(path.join(__dirname, f));
  return new Promise((resolve, reject) => mocha.run((failures) => (failures ? reject(new Error(`${failures} test(s) failed`)) : resolve())));
}
