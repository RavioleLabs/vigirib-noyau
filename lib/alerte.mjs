// Alerte Telegram pour les verdicts « alerte » et « à vérifier ».
// ÉTEINTE par défaut : il faut VIGI_TELEGRAM=on, TELEGRAM_BOT_TOKEN et TELEGRAM_CHAT_ID.
// Le jeton ne vit que sur le serveur qui envoie, jamais dans un fichier local ni dans le dépôt.
// Le message ne contient jamais d'IBAN complet : seulement les masques des raisons.

const TITRE={alerte:'ALERTE faux RIB possible',a_verifier:'À vérifier avant de payer'};

export function texteAlerte(verdict,mail){
  return [
    `${TITRE[verdict.niveau]}`,
    `De : ${mail.nomDe?mail.nomDe+' ':''}<${mail.de}>`,
    `Objet : ${mail.objet}`,
    '',
    ...verdict.raisons.map(r=>'- '+r),
    '',
    'Avant tout virement : appelez le fournisseur au numéro que vous connaissez déjà, jamais celui du mail.',
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
