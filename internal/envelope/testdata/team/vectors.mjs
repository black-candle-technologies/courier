// Independent ECMAScript RFC 8785 subset + Node Ed25519 oracle. Synthetic keys
// only; do not use these public fixtures as operational identities.
// Run: node vectors.mjs --write (intentional fixture revision), or without args
// to verify the committed fixture byte-for-byte. No packages or network needed.
import {createHash, createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
const path = new URL('./golden.json', import.meta.url);
function jcs(v) {
  if (v === null) return 'null';
  if (typeof v === 'string') {
    if (!/^[\x20-\x7e]*$/.test(v)) throw Error('outside ASCII wire grammar');
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map(k => jcs(k) + ':' + jcs(v[k])).join(',') + '}';
  throw Error('outside team grammar');
}
const sha = b => 'sha256:' + createHash('sha256').update(b).digest('hex');
const b64 = b => b.toString('base64url');
function key(n) {
 const privateKey = createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,n)]),format:'der',type:'pkcs8'});
 const publicKey = createPublicKey(privateKey);
 return {privateKey, publicKey, address:'ed25519:' + b64(publicKey.export({format:'der',type:'spki'}).subarray(-32))};
}
const keys = [null,key(1),key(2),key(3)];
function payload(o) { const {signatures,...p}=o; return jcs(p); }
function hash(o) {return sha(payload(o));}
function signed(p, roles) {
 const bytes=Buffer.from(p.schema+'\0'+payload(p));
 return {...p,signatures:roles.map(([role,n])=>{
  const sig=sign(null,bytes,keys[n].privateKey);
  if (!verify(null,bytes,keys[n].publicKey,sig)) throw Error('signature');
  return {role,address:keys[n].address,sig:b64(sig)};
 })};
}
const seed={relay_origin:'https://relay.example:8470',genesis_owner:keys[1].address,genesis_nonce:b64(Buffer.alloc(32,9))};
const root={...seed,team_id:sha('courier.team.id.v1\0'+jcs(seed)),genesis_root:sha('courier.team.genesis.v1\0'+jcs(seed))};
const policy={visibility:'private',history_disclosure:'current_and_future_members',removal_policy:'owner_dependent_with_local_blocking'};
const suite='ed25519-x25519-naclbox-v1';
const binding={...root,owner:keys[1].address,owner_epoch:'1',invite_id:b64(Buffer.concat([Buffer.from([1]),Buffer.alloc(31)])),nonce:b64(Buffer.concat([Buffer.from([2]),Buffer.alloc(31)])),handle:'alice',member_address:keys[2].address,...policy,issued_at:'2026-10-08T00:00:00Z',expires_at:'2026-10-09T00:00:00Z'};
const invitation=signed({...binding,schema:'courier.team.invitation.v1',suite},[['owner',1]]);
const acceptance=signed({...binding,schema:'courier.team.acceptance.v1',suite,invitation_hash:hash(invitation),accepted_at:'2026-10-08T00:00:00Z'},[['member',2]]);
const genesis=signed({...root,schema:'courier.team.roster.v1',suite,slug:'crew',version:'1',previous_hash:null,owner:keys[1].address,owner_epoch:'1',owner_transition_hash:null,issued_at:binding.issued_at,expires_at:binding.expires_at,status:'active',...policy,members:[{handle:'alice',address:keys[2].address,consent_hash:hash(acceptance)}]},[['owner',1]]);
const transition=signed({...root,schema:'courier.team.owner-transition.v1',suite,previous_certificate_hash:null,old_owner:keys[1].address,new_owner:keys[3].address,new_owner_epoch:'2',effective_version:'2',previous_roster_hash:hash(genesis)},[['old_owner',1],['new_owner',3]]);
const transfer=signed({...genesis,version:'2',previous_hash:hash(genesis),owner:keys[3].address,owner_epoch:'2',owner_transition_hash:hash(transition)},[['old_owner',1],['new_owner',3]]);
const renewal=signed({...transfer,version:'3',previous_hash:hash(transfer),owner_transition_hash:null,issued_at:'2026-10-10T00:00:00Z',expires_at:'2026-10-11T00:00:00Z'},[['owner',3]]);
const tombstone=signed({...renewal,version:'4',previous_hash:hash(renewal),status:'deleted',members:[]},[['owner',3]]);
const vectors=Object.entries({invitation,acceptance,genesis,transition,transfer,renewal,tombstone}).map(([name,wire])=>({name,wire,canonical_payload:payload(wire),signing_hex:Buffer.from(wire.schema+'\0'+payload(wire)).toString('hex'),payload_hash:hash(wire)}));
const encoded=JSON.stringify({revision:'packet-b-v1',root,vectors},null,2)+'\n';
if(process.argv.includes('--write'))writeFileSync(path,encoded);else if(readFileSync(path,'utf8')!==encoded)throw Error('golden mismatch');
console.log(`Verified ${vectors.length} independent ECMAScript canonical/signature vectors`);
