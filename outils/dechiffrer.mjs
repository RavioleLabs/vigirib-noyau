// Déchiffre une demande de connexion reçue par mail et la dépose sur le serveur du service.
// Usage : node outils/dechiffrer.mjs < mail.txt
// Le déchiffrement se fait ici : la clé privée ne quitte pas cet ordinateur. La configuration, avec une clé d'empreinte neuve,
// part directement par SSH dans ~/.vigi/clients/<entreprise>.env (0600) sur le serveur, sans être écrite sur cet ordinateur.
// Le service la prend au passage suivant. Le mot de passe n'est JAMAIS affiché.
import {privateDecrypt,constants,randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {DEBUT,FIN} from '../navigateur/chiffrement.js';
import {slug,deposerClient} from './serveur.mjs';

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
  const c=dechiffrer(readFileSync(0,'utf8'),cle),nom=slug(c.entreprise);
  await deposerClient(nom,envDuClient(c));
  console.log(`Configuration déposée sur le serveur : ~/.vigi/clients/${nom}.env (boîte ${c.utilisateur} sur ${c.hote}, alertes vers ${c.alertes||'personne'}). Rien n’est écrit sur cet ordinateur ; le mot de passe n’est pas affiché.`);
}
