const {createPublicKey,verify,createHash}=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const key=fs.readFileSync(path.join(__dirname,'publisher-public-key.txt'),'utf8').trim();
const dir=process.argv[2];
const envelope=JSON.parse(fs.readFileSync(path.join(dir,'update.json'),'utf8'));
const payload=Buffer.from(envelope.payload,'base64');
if(!verify('SHA256',payload,createPublicKey({key:Buffer.from(key,'base64'),format:'der',type:'spki'}),Buffer.from(envelope.signature,'base64')))throw Error('Invalid publisher signature');
const data=JSON.parse(payload);
if(data.schema!==1 || data.tag!==process.env.RELEASE_TAG)throw Error('Wrong release tag');
for(const platform of ['android','windows']){
 const entry=data[platform],expected=`qingcun-${platform}-${entry.version}.${platform==='android'?'apk':'zip'}`;
 if(entry.asset!==expected || !/^\d+\.\d+\.\d+$/.test(entry.version) || !Number.isSafeInteger(entry.code) || entry.code<1)throw Error('Invalid release fields');
 const file=fs.readFileSync(path.join(dir,expected));
 if(file.length!==entry.size || createHash('sha256').update(file).digest('hex')!==entry.sha256.toLowerCase())throw Error(`Invalid ${platform} package`);
 console.log(`${platform} ${entry.version}: signature, size and SHA-256 verified`);
}
