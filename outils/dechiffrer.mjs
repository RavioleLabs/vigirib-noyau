// Déchiffre une demande de connexion reçue par mail et écrit la configuration du client.
// Usage : node outils/dechiffrer.mjs < mail.txt
// Écrit ~/.vigirib-clients/<entreprise>.env (0600), avec une clé d'empreinte neuve ; n'affiche JAMAIS le mot de passe.
// Ce fichier se copie ensuite dans ~/.vigi/clients/ sur le serveur : le service le prend au passage suivant.
import {privateDecrypt,constants,randomBytes} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,existsSync} from 'node:fs';
import {homedir} from 'node:os';
import {DEBUT,FIN} from '../navigateur/chiffrement.js';

export function dechiffrer(texte,clePrivee){
  const debut=texte.indexOf(DEBUT),fin=texte.indexOf(FIN);
  if(debut<0||fin<debut)throw Error('Aucun bloc de connexion Vigirib dans ce texte.');
  const chiffre=Buffer.from(texte.slice(debut+DEBUT.length,fin).replace(/\s/g,''),'base64');
  const clair=privateDecrypt({key:clePrivee,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},chiffre);
  const d=JSON.parse(clair.toString('utf8'));
  const champ=nom=>(new RegExp(`^${nom} : (.*)$`,'m').exec(texte)?.[1]||'').trim();
  return {...d,entreprise:champ('Entreprise'),alertes:champ('Alertes'),messagerie:champ('Messagerie')};
}

export function envDuClient(c){
  const propre=v=>String(v??'').replace(/[\r\n]/g,'');
  return [`# ${propre(c.entreprise)} (${propre(c.messagerie)})`,`IMAP_HOTE=${propre(c.hote)}`,`IMAP_PORT=${propre(c.port||993)}`,
    `IMAP_UTILISATEUR=${propre(c.utilisateur)}`,`IMAP_MOT_DE_PASSE=${propre(c.motDePasse)}`,`IMAP_BOITE=${propre(c.boite||'INBOX')}`,
    `VIGI_ALERTE_MAIL=${propre(c.alertes)}`,
    // Clé d'empreinte propre à chaque entreprise, comme le promet le site.
    `VIGI_CLE=${c.cle||randomBytes(32).toString('hex')}`,''].join('\n');
}

if(import.meta.url===`file://${process.argv[1]}`){
  const cle=readFileSync(process.env.VIGIRIB_CLE_PRIVEE||`${homedir()}/.vigirib-installation-cle.pem`,'utf8');
  const c=dechiffrer(readFileSync(0,'utf8'),cle);
  const dossier=`${homedir()}/.vigirib-clients`;mkdirSync(dossier,{recursive:true,mode:0o700});
  const nom=(c.entreprise||'client').normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')||'client';
  const fichier=`${dossier}/${nom}.env`;
  if(existsSync(fichier)){console.error(`${fichier} existe déjà : rien n'est écrasé.`);process.exit(1);}
  writeFileSync(fichier,envDuClient(c),{mode:0o600});
  console.log(`Configuration écrite : ${fichier} (boîte ${c.utilisateur} sur ${c.hote}, alertes vers ${c.alertes||'personne'}). Le mot de passe n'est pas affiché.`);
}
