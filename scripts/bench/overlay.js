// Gate image helper: replace the vendored (brotli) payload of the platform package with the candidate binary, so the
// launcher installs the candidate (not the npm one) into $FUIGO_HOME/bin on first launch.
const z = require('zlib'), f = require('fs');
const dest = '/usr/local/lib/node_modules/fuigo/node_modules/@fuigo/linux-x64/bin/fuigo.br';
f.writeFileSync(dest, z.brotliCompressSync(f.readFileSync('/tmp/native/fuigo-native'), { params: { [z.constants.BROTLI_PARAM_QUALITY]: 5 } }));
