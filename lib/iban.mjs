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
const LONGUEURS={FR:27,MC:27,IT:27,DE:22,GB:22,IE:22,BE:16,NL:18,LU:20,AT:20,CH:21,ES:24,PT:25};

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
