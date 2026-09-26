// Alerte Telegram pour les verdicts « alerte » et « à vérifier ».
// ÉTEINTE par défaut : il faut VIGI_TELEGRAM=on, TELEGRAM_BOT_TOKEN et TELEGRAM_CHAT_ID.
// Le jeton ne vit que sur le serveur qui envoie, jamais dans un fichier local ni dans le dépôt.
// Le message ne contient jamais d'IBAN complet : seulement les masques des raisons.

const TITRE={alerte:'ALERTE faux RIB possible',a_verifier:'À vérifier avant de payer'};

// Le conseil suit la menace : un piège à identifiants se déjoue sans cliquer, un changement de RIB par un appel.
export function conseils(verdict,qui='le fournisseur'){
  const lien='Ne cliquez sur aucun lien du mail et n’y saisissez aucun identifiant : allez sur le site que vous connaissez déjà en tapant son adresse vous-même.';
  const appel=`Avant tout virement : appelez ${qui} au numéro que vous connaissez déjà, jamais celui du mail.`;
  return [...(verdict.piege?[lien]:[]),...(!verdict.piege||verdict.ibans?.length?[appel]:[])];
}

export function texteAlerte(verdict,mail){
  return [
    `${TITRE[verdict.niveau]}`,
    `De : ${mail.nomDe?mail.nomDe+' ':''}<${mail.de}>`,
    `Objet : ${mail.objet}`,
    '',
    ...verdict.raisons.map(r=>'- '+r),
    '',
    ...conseils(verdict),
  ].join('\n');
}

export function creerAlerte({
  mode=process.env.VIGI_TELEGRAM||'off',jeton=process.env.TELEGRAM_BOT_TOKEN,chat=process.env.TELEGRAM_CHAT_ID,
  fetchImpl=fetch,journal=()=>{},
}={}){
  if(mode!=='on'||!jeton||!chat)return null;
  return async(verdict,mail)=>{
    if(verdict.niveau==='ok')return false;
    try{
      const res=await fetchImpl(`https://api.telegram.org/bot${jeton}/sendMessage`,{method:'POST',
        headers:{'Content-Type':'application/json'},signal:AbortSignal.timeout(10000),
        body:JSON.stringify({chat_id:chat,text:texteAlerte(verdict,mail).slice(0,4000),disable_web_page_preview:true})});
      if(!res.ok)journal(`Telegram a refusé l'alerte (${res.status})`);
      return res.ok;
    }catch(e){journal('Telegram injoignable : '+e.message);return false;}
  };
}
