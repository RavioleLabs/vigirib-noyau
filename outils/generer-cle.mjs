// Génère, UNE fois, la paire de clés de l'installation sécurisée.
// Clé privée : ~/.vigirib-installation-cle.pem (0600, jamais dans le dépôt ni sur le site). Clé publique : cle-installation.pem.
// Refuse d'écraser une clé existante : une nouvelle clé rendrait illisibles les connexions déjà chiffrées.
import {generateKeyPairSync} from 'node:crypto';
import {writeFileSync,existsSync} from 'node:fs';
import {homedir} from 'node:os';

const prive=process.env.VIGIRIB_CLE_PRIVEE||`${homedir()}/.vigirib-installation-cle.pem`;
const publique=new URL('../cle-installation.pem',import.meta.url);
if(existsSync(prive)){console.error(`Une clé privée existe déjà (${prive}) : rien n'est écrasé.`);process.exit(1);}
const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:4096,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
writeFileSync(prive,privateKey,{mode:0o600});
writeFileSync(publique,publicKey);
console.log(`Clé privée : ${prive} (lisible par vous seul). Clé publique : cle-installation.pem.`);
