// Importe les IBAN de référence d'un client (reçus chiffrés par mail depuis /installation/import/) dans sa mémoire.
// Usage : node outils/importer-ibans.mjs <client> < mails.txt   (un ou plusieurs blocs « LISTE VIGIRIB » à la suite)
// Lit la clé d'empreinte du client dans ~/.vigirib-clients/<client>.env, écrit ~/.vigirib-clients/<client>/registre.json.
// N'affiche AUCUN IBAN : seulement le nombre importé.
import {privateDecrypt,constants,createDecipheriv} from 'node:crypto';
import {inflateRawSync} from 'node:zlib';
import {readFileSync,mkdirSync} from 'node:fs';
import {homedir} from 'node:os';
import {parseEnv} from 'node:util';
import {DEBUT_LISTE,FIN_LISTE} from '../navigateur/chiffrement.js';
import {cleValide,normaliser} from '../lib/iban.mjs';
import {creerRegistre} from '../lib/registre.mjs';

export function dechiffrerListes(texte,clePrivee){
  const listes=[];
  for(const m of texte.matchAll(new RegExp(`${DEBUT_LISTE}([\\s\\S]*?)${FIN_LISTE}`,'g'))){
    const tout=Buffer.from(m[1].replace(/\s/g,''),'base64');
    const n=tout.readUInt16BE(0),cleAes=privateDecrypt({key:clePrivee,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},tout.subarray(2,2+n));
    const iv=tout.subarray(2+n,14+n),corps=tout.subarray(14+n);
    const d=createDecipheriv('aes-256-gcm',cleAes,iv);d.setAuthTag(corps.subarray(corps.length-16));
    const clair=Buffer.concat([d.update(corps.subarray(0,corps.length-16)),d.final()]);
    listes.push(JSON.parse(inflateRawSync(clair).toString('utf8')));
  }
  if(!listes.length)throw Error('Aucune liste Vigirib dans ce texte.');
  return listes;
}

export function importer(listes,registre,{date=new Date().toISOString()}={}){
  let n=0,rejetes=0;
  for(const l of listes)for(const iban of l.ibans||[]){const i=normaliser(String(iban));if(cleValide(i)){registre.marquerPaye(i,date);n++;}else rejetes++;}
  return {importes:n,rejetes};
}

if(import.meta.url===`file://${process.argv[1]}`){
  const client=process.argv[2];
  if(!client||!/^[a-z0-9-]+$/.test(client)){console.error('Usage : node outils/importer-ibans.mjs <client> < mails.txt');process.exit(1);}
  const conf=parseEnv(readFileSync(`${homedir()}/.vigirib-clients/${client}.env`,'utf8'));
  const listes=dechiffrerListes(readFileSync(0,'utf8'),readFileSync(process.env.VIGIRIB_CLE_PRIVEE||`${homedir()}/.vigirib-installation-cle.pem`,'utf8'));
  const dossier=`${homedir()}/.vigirib-clients/${client}`;mkdirSync(dossier,{recursive:true,mode:0o700});
  const registre=creerRegistre(`${dossier}/registre.json`,{cle:Buffer.from(conf.VIGI_CLE,'hex')});
  const r=importer(listes,registre);registre.sauver();
  console.log(`${r.importes} IBAN de référence importés pour ${client} (${r.rejetes} rejetés, clé invalide). Aucun IBAN n'est affiché ni stocké en clair.`);
}
