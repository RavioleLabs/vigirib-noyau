// IBAN : repérage dans du texte libre, normalisation et contrôle de clé (mod 97).
// Le contrôle de clé écarte les faux positifs (références, SIRET, numéros de facture).
// Les factures françaises donnent aussi souvent le RIB en colonnes (banque, guichet, compte, clé) :
// on le convertit en IBAN pour que les deux écritures d'un même compte aient la même empreinte.

// Groupes séparés par une espace, une espace insécable, un tiret ou un point.
const CANDIDAT=/\b([A-Z]{2}\d{2}(?:[ .\-]?[A-Z0-9]){10,30})/g;

export const normaliser=s=>s.replace(/[\s.\-]/g,'').toUpperCase();
const espacesNormales=s=>String(s).replace(/[   ]/g,' ');

function mod97(chiffres){let reste=0;for(const ch of chiffres)reste=(reste*10+Number(ch))%97;return reste;}
const lettresEnChiffres=s=>s.replace(/[A-Z]/g,c=>String(c.charCodeAt(0)-55));

export function cleValide(iban){
  const s=normaliser(iban);
  if(!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s))return false;
  return mod97(lettresEnChiffres(s.slice(4)+s.slice(0,4)))===1;
}

export function avecCle(pays,bban){
  return pays+String(98-mod97(lettresEnChiffres(bban+pays+'00'))).padStart(2,'0')+bban;
}

// Clé RIB française : 97 - ((89 × banque + 15 × guichet + 3 × compte) mod 97), lettres du compte converties.
const LETTRE_RIB={A:1,J:1,B:2,K:2,S:2,C:3,L:3,T:3,D:4,M:4,U:4,E:5,N:5,V:5,F:6,O:6,W:6,G:7,P:7,X:7,H:8,Q:8,Y:8,I:9,R:9,Z:9};
export function cleRibValide(banque,guichet,compte,cle){
  const c=compte.replace(/[A-Z]/g,l=>String(LETTRE_RIB[l]));
  return 97-((89*Number(banque)+15*Number(guichet)+3*Number(c))%97)===Number(cle);
}

// RIB en colonnes : « Banque 30004 Guichet 00031 Compte 12345678901 Clé 43 », ou une ligne d'en-têtes puis une ligne de valeurs.
function ribs(texte){
  const out=[];
  if(!/banque/i.test(texte)||!/guichet/i.test(texte))return out;
  for(const m of texte.toUpperCase().matchAll(/\b(\d{5})\D{0,40}?\b(\d{5})\D{0,40}?\b([A-Z0-9]{11})\D{0,30}?\b(\d{2})\b/g)){
    const [,banque,guichet,compte,cle]=m;
    if(/\d/.test(compte)&&cleRibValide(banque,guichet,compte,cle))out.push(avecCle('FR',banque+guichet+compte+cle));
  }
  return out;
}

// Longueur fixe par pays : un IBAN écrit par groupes peut avaler le mot suivant, on coupe à la bonne longueur.
// On ne raccourcit jamais au hasard : une chance sur 97 de tomber sur une clé valide ferait des faux IBAN.
// Tous les pays du registre IBAN : les comptes de néobanques étrangères (Revolut en Lituanie, par exemple) sont un
// grand classique des faux RIB, un pays manquant laissait passer un IBAN écrit par groupes.
export const LONGUEURS={AD:24,AE:23,AL:28,AT:20,AZ:28,BA:20,BE:16,BG:22,BH:22,BR:29,BY:28,CH:21,CR:22,CY:28,CZ:24,DE:22,DK:18,
  DO:28,EE:20,EG:29,ES:24,FI:18,FO:18,FR:27,GB:22,GE:22,GI:23,GL:18,GR:27,GT:28,HR:21,HU:28,IE:22,IL:23,IQ:23,IS:26,IT:27,
  JO:30,KW:30,KZ:20,LB:28,LC:32,LI:21,LT:20,LU:20,LV:21,MC:27,MD:24,ME:22,MK:19,MR:27,MT:31,MU:30,NL:18,NO:15,PK:24,PL:28,
  PS:29,PT:25,QA:29,RO:24,RS:22,SA:24,SC:31,SE:24,SI:19,SK:24,SM:27,ST:25,SV:28,TL:23,TN:24,TR:26,UA:29,VA:22,VG:24,XK:20};

export function extraire(texte){
  const t=espacesNormales(texte),vus=new Set();
  for(const m of t.toUpperCase().matchAll(CANDIDAT)){
    const s=normaliser(m[1]),l=LONGUEURS[s.slice(0,2)];
    const iban=l?s.slice(0,l):s;
    if((!l||s.length>=l)&&cleValide(iban))vus.add(iban);
  }
  for(const iban of ribs(t))vus.add(iban);
  return [...vus];
}

export const masquer=iban=>iban.slice(0,4)+'\u00a0…\u00a0'+iban.slice(-4);
