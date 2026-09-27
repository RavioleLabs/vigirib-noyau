// Réception des transferts dans la boîte de Vigirib (analyse@vigirib.com).
// Deux usages :
//   1. Protection automatique : le client fait suivre (redirection filtrée) les mails de sa boîte de factures.
//      On reconnaît le client par l'adresse de sa boîte, on analyse avec SA mémoire, on l'alerte par mail.
//   2. Essai ou dépannage : n'importe qui transfère UN mail douteux ; on répond avec le verdict (sans historique).
// Dans tous les cas, chaque copie est SUPPRIMÉE de notre boîte juste après l'analyse (promesse RGPD du site).
// Les règles de détection (analyser, memoriser) sont passées en paramètre : elles ne sont pas publiées, ce module l'est.
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {lireEml,adresse} from './eml.mjs';
import {creerRegistre,organisation} from './registre.mjs';
import {texteAlerte,conseils} from './alerte.mjs';
import {sujetAlerte} from './alerte-mail.mjs';

const ADRESSE=/[^\s<>"'(),;:[\]]+@[^\s<>"'(),;:[\]]+\.[a-z]{2,}/gi;
const adresses=s=>[...String(s||'').matchAll(ADRESSE)].map(m=>m[0].toLowerCase());

// Transfert dans le corps : bloc d'en-têtes (De/From, Objet/Subject, À/To, Date/Envoyé) puis le mail d'origine.
const LIGNE_DE=/^[ \t>]*(?:De|From)\s?:\s*(.+)$/im;
function transfertEnLigne(mail){
  if(!/^\s*(?:(?:TR|Tr|Fwd?|FW|Fw|Transf\.?)\s*:)/.test(mail.objet)&&!/(forwarded message|message transf[ée]r[ée]|mail transf[ée]r[ée]|message r[ée]exp[ée]di[ée]|original message)/i.test(mail.texte))return null;
  const m=LIGNE_DE.exec(mail.texte);
  if(!m)return null;
  const apres=mail.texte.slice(m.index);
  const [entete,...reste]=apres.split(/\n\s*\n/);
  const champ=re=>(re.exec(entete)?.[1]||'').trim();
  const de=adresses(m[1])[0];
  if(!de)return null;
  return {...mail,de,nomDe:m[1].replace(/<[^>]*>|\[mailto:[^\]]*\]/g,'').replace(/"/g,'').trim(),
    objet:champ(/^[ \t>]*(?:Objet|Subject)\s?:\s*(.+)$/im)||mail.objet.replace(/^\s*(?:TR|Fwd?|FW)\s*:\s*/i,''),
    repondreA:null,texte:reste.join('\n\n'),
    destinataires:adresses(champ(/^[ \t>]*(?:À|A|To)\s?:\s*(.+)$/im)+' '+champ(/^[ \t>]*Cc\s?:\s*(.+)$/im))};
}

// Rend le mail d'origine à analyser, et qui nous l'a transféré.
export function deballer(mail){
  const par=mail.de;
  if(mail.joints?.length){const o=lireEml(mail.joints[0]);return {mail:o,manuel:true,par,destinataires:adresses(`${o.entetes.to||''} ${o.entetes.cc||''}`)};}
  const enLigne=transfertEnLigne(mail);
  if(enLigne)return {mail:enLigne,manuel:true,par,destinataires:enLigne.destinataires};
  // Redirection transparente (filtre, règle, transfert automatique) : le mail est déjà celui d'origine.
  const h=mail.entetes;
  return {mail,manuel:false,par:null,destinataires:adresses(`${h.to||''} ${h.cc||''} ${h['x-forwarded-for']||''} ${h['x-original-to']||''} ${h['resent-from']||''}`)};
}

// Le client concerné. Redirection automatique : par les destinataires (sa boîte déclarée, adresse ou domaine).
// Transfert à la main : UNIQUEMENT par l'adresse de celui qui transfère, jamais par les destinataires écrits
// dans le mail transféré, sinon n'importe qui pourrait déclencher des alertes chez un client.
export function trouverClient(deballe,clients){
  const cands=(deballe.manuel?[deballe.par]:deballe.destinataires).filter(Boolean).map(a=>a.toLowerCase());
  return clients.find(c=>c.boites.some(b=>cands.some(a=>b.includes('@')?a===b:a.endsWith('@'+b))))||null;
}

// Mail de confirmation de transfert Gmail : on renvoie le code au demandeur.
export function confirmationGmail(mail){
  if(!/forwarding-noreply@google\.com$/.test(mail.de))return null;
  const code=/\(#(\d{6,12})\)/.exec(mail.objet)?.[1]||/\b(\d{9})\b/.exec(mail.texte)?.[1];
  const demandeur=adresses(mail.objet).find(a=>!a.endsWith('google.com'))||adresses(mail.texte).find(a=>!/google\.com$|vigirib\.com$/.test(a));
  return code&&demandeur?{code,demandeur}:null;
}

// Serveurs dont on croit le verdict : ceux de notre hébergeur de messagerie (OVHcloud), nom exact ou sous-domaine.
const SERVEURS_AUTH=(process.env.VIGI_SERVEURS_AUTH||'mail.ovh.net,garm.ovh').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);

// Répondre seulement si l'expéditeur est authentifié, pour ne jamais écrire à une adresse usurpée.
// Seul compte l'en-tête Authentication-Results posé par notre hébergeur, le plus haut du mail (lireEml ne garde que lui) ;
// jamais un en-tête ARC ni un en-tête que l'expéditeur aurait écrit lui-même. Et seulement pour le domaine de l'expéditeur
// (alignement, comme DMARC) : DMARC, DKIM ou SPF « pass » pour ce domaine, ou envoi authentifié chez l'hébergeur
// (auth=pass) par le compte même de l'expéditeur.
export function authentifie(mail,{serveurs=SERVEURS_AUTH}={}){
  const [id='',...methodes]=String(mail.entetes?.['authentication-results']||'').split(';').map(x=>x.trim());
  const serveur=id.toLowerCase();
  if(!serveurs.some(s=>serveur===s||serveur.endsWith('.'+s)))return false;
  const de=String(mail.de||'').toLowerCase(),dom=de.split('@')[1]||'';
  if(!dom)return false;
  const aligne=v=>{const d=String(v||'').toLowerCase().replace(/^.*@/,'').replace(/[>)"]+$/,'');return !!d&&organisation(d)===organisation(dom);};
  return methodes.some(m=>(/^dmarc=pass\b/i.test(m)&&aligne(/\bheader\.from=([^\s;]+)/i.exec(m)?.[1]))
    ||(/^dkim=pass\b/i.test(m)&&aligne(/\bheader\.d=([^\s;]+)/i.exec(m)?.[1]))
    ||(/^spf=pass\b/i.test(m)&&aligne(/\bsmtp\.mailfrom=([^\s;]+)/i.exec(m)?.[1]))
    ||(/^auth=pass\b/i.test(m)&&/\bsmtp\.auth=([^\s;]+)/i.exec(m)?.[1]?.toLowerCase()===de));
}


const LIBELLE={alerte:'Alerte',a_verifier:'À vérifier',ok:'Rien de suspect repéré'};
export function texteReponse(verdict,original,{sansHistorique}){
  return [
    'Bonjour,','',
    `Vous nous avez transféré le mail « ${original.objet} » de ${original.nomDe?original.nomDe+' ':''}<${original.de}>.`,'',
    `Verdict : ${LIBELLE[verdict.niveau]}`,
    ...verdict.raisons.map(r=>'- '+r),
    ...(verdict.niveau==='ok'?['Cela ne prouve pas que le mail est authentique : un changement de RIB se vérifie toujours par téléphone.']:conseils(verdict,'l’expéditeur')),'',
    ...(sansHistorique?['Ce verdict est fait sans historique : Vigirib ne connaît pas encore les IBAN que vous avez déjà payés. Pour être alerté automatiquement quand l’IBAN d’un fournisseur change : https://vigirib.com/installation/','']:[]),
    'Votre mail a été supprimé de notre boîte juste après l’analyse.','','Vigirib',
  ].join('\n');
}

function compteur(dossier){
  const f=join(dossier,'reception-compteur.json');let c={jour:'',total:0,par:{}};
  try{c=JSON.parse(readFileSync(f,'utf8'));}catch{}
  const jour=new Date().toISOString().slice(0,10);if(c.jour!==jour)c={jour,total:0,par:{}};
  return {c,peut:(a,max,maxTotal)=>(c.par[a]||0)<max&&c.total<maxTotal,compter:a=>{c.par[a]=(c.par[a]||0)+1;c.total++;},sauver:()=>writeFileSync(f,JSON.stringify(c),{mode:0o600})};
}

// Un passage sur la boîte de réception. `boite` est un client IMAP ouvert en mode propriétaire.
// `adresseReception` : notre propre adresse, pour reconnaître nos alertes et réponses renvoyées par un filtre de transfert.
export async function traiterReception({boite,clients,dossier,envoyer,analyser,memoriser,jev=null,journal=()=>{},maxParExpediteur=10,maxParJour=300,
  adresseReception=null,serveursAuth}){
  if(typeof analyser!=='function'||typeof memoriser!=='function')throw Error('traiterReception : analyser et memoriser sont obligatoires');
  mkdirSync(dossier,{recursive:true,mode:0o700});
  const quota=compteur(dossier),bilan={analyses:0,alertes:0,reponses:0,codes:0,ignores:0};
  const auth=m=>authentifie(m,serveursAuth?{serveurs:serveursAuth}:{});
  const notreDomaine=String(adresseReception||'').split('@')[1]?.toLowerCase()||null;
  const envoyerSurQuota=async(a,sujet,texte)=>{
    if(!quota.peut(a,maxParExpediteur,maxParJour)){journal('quota de réponses atteint pour '+a);return false;}
    try{await envoyer({a:[a],sujet,texte});quota.compter(a);return true;}catch(e){journal('réponse non envoyée : '+e.message);return false;}
  };
  for(const uid of await boite.uidsApres(0)){
    try{
      const brut=await boite.lire(uid);if(!brut)continue;
      const mail=lireEml(brut);
      const gmail=confirmationGmail(mail);
      if(gmail){
        if(await envoyerSurQuota(gmail.demandeur,'Vigirib : votre code de confirmation Gmail',
          `Bonjour,\n\nGmail nous a transmis le code de confirmation de votre transfert vers Vigirib : ${gmail.code}\n\nSaisissez-le dans Gmail, rubrique Transfert et POP/IMAP, pour terminer l’installation.\n\nVigirib`))bilan.codes++;
        continue;
      }
      const d=deballer(mail);
      // Nos propres alertes et réponses, renvoyées par un filtre de transfert : rien à analyser, et surtout pas de boucle.
      if(notreDomaine&&String(d.mail.de||'').toLowerCase().endsWith('@'+notreDomaine)){bilan.ignores++;continue;}
      const client=trouverClient(d,clients);
      if(client){
        mkdirSync(join(dossier,client.nom),{recursive:true,mode:0o700});
        const registre=creerRegistre(join(dossier,client.nom,'registre.json'),{cle:Buffer.from(client.cle,'hex')});
        const verdict=await analyser(d.mail,registre,{jev:client.jev===false?null:jev});
        const apprentissage=client.actifDepuis&&d.mail.date&&d.mail.date<new Date(client.actifDepuis);
        memoriser(d.mail,apprentissage?{...verdict,niveau:'ok'}:verdict,registre);registre.sauver();bilan.analyses++;
        if(!apprentissage&&verdict.niveau!=='ok'){
          for(const a of client.alertes)await envoyer({a:[a],sujet:sujetAlerte(verdict,d.mail),texte:texteAlerte(verdict,d.mail)+'\n\nCe message est envoyé automatiquement par Vigirib.'}).catch(e=>journal('alerte non envoyée : '+e.message));
          bilan.alertes++;
        }
        if(d.manuel&&auth(mail)&&await envoyerSurQuota(adresse(d.par),`Vigirib : ${LIBELLE[verdict.niveau].toLowerCase()} pour « ${d.mail.objet.slice(0,80)} »`,texteReponse(verdict,d.mail,{sansHistorique:false})))bilan.reponses++;
      }else if(d.manuel&&auth(mail)){
        // Essai : analyse sans historique, mémoire jetable.
        const verdict=await analyser(d.mail,creerRegistre(null,{cle:randomBytes(32)}),{jev});bilan.analyses++;
        if(await envoyerSurQuota(adresse(d.par),`Vigirib : ${LIBELLE[verdict.niveau].toLowerCase()} pour « ${d.mail.objet.slice(0,80)} »`,texteReponse(verdict,d.mail,{sansHistorique:true})))bilan.reponses++;
      }else bilan.ignores++;
    }catch(e){journal(`mail ${uid} non analysé : ${e.message}`);}
    finally{await boite.supprimer(uid).catch(e=>journal(`suppression ${uid} impossible : ${e.message}`));}
  }
  await boite.purger();quota.sauver();
  return bilan;
}
