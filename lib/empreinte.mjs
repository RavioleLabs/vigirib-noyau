// Empreinte d'IBAN : HMAC-SHA256 avec une clé secrète propre à chaque client.
// Un SHA simple ne suffit pas : un IBAN français a ~10^11 valeurs possibles une fois la banque connue,
// on les essaie toutes en quelques heures. Avec la clé, l'empreinte est à sens unique et reste comparable.
// On ne garde jamais l'IBAN en clair : seulement l'empreinte et un masque pour l'affichage.
import {createHmac,randomBytes} from 'node:crypto';
import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {masquer} from './iban.mjs';

export function creerEmpreinte(cle){
  if(!cle||cle.length<32)throw Error('Clé d\'empreinte absente ou trop courte (32 octets minimum).');
  return iban=>({empreinte:createHmac('sha256',cle).update(iban).digest('hex'),masque:masquer(iban)});
}

// Clé : variable VIGI_CLE (hex), sinon fichier à part du registre, créé une fois en 0600.
// Registre et clé ne doivent jamais être stockés ni sauvegardés au même endroit.
export function chargerCle(chemin=null){
  if(process.env.VIGI_CLE)return Buffer.from(process.env.VIGI_CLE,'hex');
  if(!chemin)return randomBytes(32);
  if(!existsSync(chemin))writeFileSync(chemin,randomBytes(32).toString('hex'),{mode:0o600});
  return Buffer.from(readFileSync(chemin,'utf8').trim(),'hex');
}
