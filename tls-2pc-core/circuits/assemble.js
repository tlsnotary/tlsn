const casm = require('./casmbundle');
global.fs = require('fs'); 

for (let i=1; i<8; i++){
    global.fs.writeFileSync('c'+i+'.out', casm.parseAndAssemble('c'+i+'.casm'));
}
