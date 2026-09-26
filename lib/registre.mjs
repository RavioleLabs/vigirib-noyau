// Mémoire des IBAN : pour chaque fournisseur (domaine d'envoi), les empreintes des IBAN déjà vus.
// Aucun IBAN en clair : seulement l'empreinte (HMAC avec la clé du client) et un masque d'affichage.
// Un IBAN n'entre dans la mémoire qu'une fois confirmé : un IBAN signalé reste « en attente »
// tant qu'un humain ne l'a pas validé, sinon l'escroc serait « connu » dès son deuxième mail.
import {readFileSync,writeFileSync,existsSync,chmodSync} from 'node:fs';
import {creerEmpreinte,chargerCle} from './empreinte.mjs';

const SUFFIXES_DOUBLES=new Set(['co.uk','com.au','co.jp','com.br','gouv.fr']);
export function organisation(dom){
  const p=dom.toLowerCase().split('.');
  const deux=p.slice(-2).join('.');
  return SUFFIXES_DOUBLES.has(deux)?p.slice(-3).join('.'):deux;
}

export function creerRegistre(chemin=null,{cle=chargerCle(chemin&&chemin+'.cle')}={}){
  const empreinte=creerEmpreinte(cle);
  const etat=chemin&&existsSync(chemin)?JSON.parse(readFileSync(chemin,'utf8')):{fournisseurs:{}};
  const fiche=org=>etat.fournisseurs[org]??=({ibans:{},enAttente:{},mails:0});
  return {
    etat,
    connu:org=>!!etat.fournisseurs[org]?.mails,
    organisations:()=>Object.keys(etat.fournisseurs).filter(o=>etat.fournisseurs[o].mails),
    masquesDe:org=>Object.values(etat.fournisseurs[org]?.ibans||{}).map(i=>i.masque),
    confirme(org,iban){return !!etat.fournisseurs[org]?.ibans?.[empreinte(iban).empreinte];},
    enAttente(org,iban){return !!etat.fournisseurs[org]?.enAttente?.[empreinte(iban).empreinte];},
    vu(org,date){const f=fiche(org);f.mails++;f.premier??=date;f.dernier=date;},
    confirmer(org,iban,date){
      const {empreinte:e,masque}=empreinte(iban),f=fiche(org);
      f.ibans[e]??={masque,depuis:date,fois:0};f.ibans[e].fois++;delete f.enAttente[e];
    },
    mettreEnAttente(org,iban,date){const {empreinte:e,masque}=empreinte(iban);fiche(org).enAttente[e]??={masque,depuis:date};},
    // IBAN de référence : ceux que l'entreprise paie déjà, importés de sa compta ou de sa banque à l'installation.
    // Tant qu'il y en a, un IBAN jamais payé est signalé même au premier mail d'un fournisseur (plus de confiance au premier venu).
    marquerPaye(iban,date){const {empreinte:e,masque}=empreinte(iban);(etat.payes??={})[e]??={masque,depuis:date};},
    dejaPaye(iban){return !!etat.payes?.[empreinte(iban).empreinte];},
    aDesPayes:()=>Object.keys(etat.payes||{}).length>0,
    // Lisible par le seul compte du service, même si le fichier existait avec d'autres droits.
    sauver(){if(chemin){writeFileSync(chemin,JSON.stringify(etat,null,2),{mode:0o600});chmodSync(chemin,0o600);}},
  };
}
