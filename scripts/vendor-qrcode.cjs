const fs = require('fs');
const path = require('path');
const source = '/opt/codex/runtimes/codex-primary-runtime/dependencies/node/lib/node_modules/npm/node_modules/qrcode-terminal/vendor/QRCode';
const order = ['QRMode.js','QRErrorCorrectLevel.js','QRMaskPattern.js','QRMath.js','QRPolynomial.js','QRBitBuffer.js','QR8bitByte.js','QRRSBlock.js','QRUtil.js','index.js'];
let out = `// QRCode for JavaScript, Copyright (c) 2009 Kazuhiko Arase. MIT License.\n`;
for (const file of order) {
  let s = fs.readFileSync(path.join(source,file),'utf8');
  s = s.replace(/^var .*?= require\(.+?\);\s*$/gm,'');
  const name = file === 'index.js' ? 'QRCode' : file.replace('.js','');
  s = s.replace(/module\.exports\s*=\s*\{/,'var '+name+' = {');
  s = s.replace(/^module\.exports\s*=\s*[^;]+;\s*$/gm,'');
  out += '\n'+s+'\n';
}
out += `\nexport function qrSvg(value){const qr=new QRCode(-1,QRErrorCorrectLevel.M);qr.addData(value);qr.make();const n=qr.getModuleCount(),q=4,size=n+q*2;let p='';for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(qr.isDark(r,c))p+='<rect x="'+(c+q)+'" y="'+(r+q)+'" width="1" height="1"/>';return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+size+' '+size+'" role="img" aria-label="Código QR de acceso" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="white"/><g fill="#071b2d">'+p+'</g></svg>';}\n`;
fs.writeFileSync('worker/qrcode.js',out);
