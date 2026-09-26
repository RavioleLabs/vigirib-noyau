// Alerte par mail : le canal par défaut des PME. Envoyée par la boîte OVHcloud de Vigirib (SMTP).
// Éteinte tant que VIGI_ALERTE_MAIL (destinataires, séparés par des virgules) et la connexion SMTP ne sont pas renseignés.
// Comme sur Telegram : jamais d'IBAN complet, seulement les masques des raisons.
import {envoyerMail} from './smtp.mjs';
import {texteAlerte} from './alerte.mjs';

const TITRE={alerte:'Alerte faux RIB',a_verifier:'À vérifier avant de payer'};

export function sujetAlerte(verdict,mail){
  return `${TITRE[verdict.niveau]} : ${mail.nomDe||mail.de}${mail.objet?`, « ${mail.objet.slice(0,80)} »`:''}`;
}

export function creerAlerteMail({
  destinataires=process.env.VIGI_ALERTE_MAIL,hote=process.env.SMTP_HOTE,port=Number(process.env.SMTP_PORT||465),
  utilisateur=process.env.SMTP_UTILISATEUR,motDePasse=process.env.SMTP_MOT_DE_PASSE,
  expediteur=process.env.SMTP_EXPEDITEUR||(process.env.SMTP_UTILISATEUR?`Vigirib <${process.env.SMTP_UTILISATEUR}>`:''),
  securise=true,envoyer=envoyerMail,journal=()=>{},
}={}){
  const a=String(destinataires||'').split(',').map(s=>s.trim()).filter(s=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s));
  if(!a.length||!hote||!utilisateur||!motDePasse)return null;
  return async(verdict,mail)=>{
    if(verdict.niveau==='ok')return false;
    const texte=texteAlerte(verdict,mail)+'\n\nCe message est envoyé automatiquement par Vigirib. Répondez-y pour nous signaler une erreur.';
    try{await envoyer({hote,port,securise,utilisateur,motDePasse,de:expediteur||`Vigirib <${utilisateur}>`,a,sujet:sujetAlerte(verdict,mail),texte});return true;}
    catch(e){journal('alerte mail non envoyée : '+e.message);return false;}
  };
}
