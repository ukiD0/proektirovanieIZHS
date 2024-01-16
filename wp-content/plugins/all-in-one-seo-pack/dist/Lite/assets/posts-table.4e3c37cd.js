import{_ as b}from"./js/_plugin-vue_export-helper.abeb2ae0.js";import{o as n,c as m,a as i,x as _,k as h,b as a,l as r,D as c,t as s,C as d,H as u,m as Q,I as x,Y as L,h as R}from"./js/vue.runtime.esm-bundler.4a881941.js";import{l as X}from"./js/index.683fda17.js";import{l as Y}from"./js/index.e978df4e.js";import{l as J}from"./js/index.0b123ab1.js";import{a as K,A as W,m as N,r as S,t as z,l as $}from"./js/links.125d59c9.js";import{s as tt,t as et,T as st}from"./js/postSlug.ffc044fc.js";import{a as it}from"./js/allowed.1a0ffdc5.js";import"./js/default-i18n.3881921e.js";import{u as M,T as B}from"./js/TruSeoScore.b474bf15.js";import{l as A}from"./js/license.7b516004.js";import{B as U,e as O}from"./js/Caret.02d7c74a.js";import{C as H}from"./js/HtmlTagsEditor.3dd82072.js";import{_ as ot}from"./js/ScoreButton.ebdf14dd.js";import{C as j}from"./js/Tooltip.bcf420d9.js";import{I as nt}from"./js/IndexStatus.21a7e8cc.js";import{S as lt}from"./js/LogoGear.49550bdb.js";/* empty css                */import"./js/translations.6e7b2383.js";import"./js/constants.238e5b7b.js";import"./js/isArrayLikeObject.ab8f4241.js";import"./js/metabox.e3fb2d0a.js";import"./js/cleanForSlug.cc6d9d47.js";import"./js/toString.7b877a36.js";import"./js/_baseTrim.8725856f.js";import"./js/_stringToArray.4de3b1f3.js";import"./js/get.038a6445.js";import"./js/upperFirst.7faab9f8.js";import"./js/tags.549c2c20.js";import"./js/Editor.e4c60376.js";import"./js/UnfilteredHtml.9de32d22.js";const rt={},at={viewBox:"0 0 16 17",fill:"none",xmlns:"http://www.w3.org/2000/svg",class:"aioseo-headline-analyzer"},ct=i("path",{"fill-rule":"evenodd","clip-rule":"evenodd",d:"M10.5448 1.76771H14.6665V1.79272L10.5448 4.61008V1.76771ZM5.46515 8.08232V1.76779H1.34351V4.8899L1.34378 4.71192L5.42731 8.10819L5.46515 8.08232ZM1.34351 11.4568L5.46515 14.2652V15.0999H1.34351V11.4568ZM10.5448 10.8851L14.6665 8.14027V15.0982H10.5448V10.8851Z",fill:"currentColor"},null,-1),dt=i("path",{"fill-rule":"evenodd","clip-rule":"evenodd",d:"M5.46515 8.05739L5.42731 8.08325L1.34378 4.68698L1.34351 4.86412V1.76779H5.46515V8.05739ZM5.46515 14.2083L1.34351 11.3998V15.0999H5.46515V14.2083ZM10.5448 10.8281L14.6665 8.08332V15.0982H10.5448V10.8281ZM14.6665 1.76778L10.5448 4.58515V1.76771H14.6665V1.76778Z",fill:"currentColor"},null,-1),pt=i("path",{d:"M5.42725 9.45857L14.6665 3.14303V6.76487L5.46703 12.8912L1.33325 10.0745L1.34372 6.06231L5.42725 9.45857Z",fill:"currentColor"},null,-1),ut=[ct,dt,pt];function mt(e,l){return n(),m("svg",at,ut)}const ht=b(rt,[["render",mt]]);const _t={setup(){const{strings:e}=M();return{composableStrings:e,optionsStore:K(),searchStatisticsStore:W()}},components:{BaseButton:U,CoreHtmlTagsEditor:H,CoreScoreButton:ot,CoreTooltip:j,IndexStatus:nt,SvgAioseoLogoGear:lt,SvgHeadlineAnalyzer:ht,SvgPencil:O},mixins:[B],props:{post:Object,posts:Array},data(){return{allowed:it,postId:null,columnName:null,value:null,title:null,titleParsed:null,postDescription:null,descriptionParsed:null,imageTitle:null,imageAltTag:null,showEditTitle:!1,showEditDescription:!1,showEditImageTitle:!1,showEditImageAltTag:!1,showTruSeo:!1,isSpecialPage:!1,inspectionResult:!1,inspectionResultLoading:!0,teucu:!1,strings:N(this.composableStrings,{title:this.$t.__("Title",this.$td),description:this.$t.__("Description",this.$td),imageTitle:this.$t.__("Image Title",this.$td),imageAltTag:this.$t.__("Image Alt Tag",this.$td),saveChanges:this.$t.__("Save Changes",this.$td),discardChanges:this.$t.__("Discard Changes",this.$td),truSeoScore:this.$t.__("TruSEO Score",this.$td),headlineScore:this.$t.__("Headline Score",this.$td)}),license:A}},computed:{showIndexStatus(){var g,t,o;if(!this.$isPro||!A.hasCoreFeature("search-statistics","index-status"))return!1;const e=!this.searchStatisticsStore.unverifiedSite,l=typeof((o=(t=(g=this.optionsStore.internalOptions.internal)==null?void 0:g.searchStatistics)==null?void 0:t.profile)==null?void 0:o.key)=="string",p=this.allowed("aioseo_search_statistics_settings");return e&&l&&p}},methods:{save(){this.showEditTitle=!1,this.showEditDescription=!1,this.post.title=this.title,this.post.description=this.postDescription,S.post(this.$links.restUrl("postscreen")).send({postId:this.post.id,title:this.post.title,description:this.post.description}).then(e=>{this.titleParsed=e.body.title,this.descriptionParsed=e.body.description,this.post.titleParsed=e.body.title,this.post.descriptionParsed=e.body.description,this.$root._data.screen.base!=="upload"&&this.runAnalysis(this.post.id)}).catch(e=>{console.error(`Unable to update post with ID ${this.post.id}: ${e}`)})},saveImage(){this.showEditImageTitle=!1,this.showEditImageAltTag=!1,this.post.title=this.title,this.post.description=this.postDescription,this.post.imageTitle=this.imageTitle,this.post.imageAltTag=this.imageAltTag,S.post(this.$links.restUrl("postscreen")).send({postId:this.post.id,isMedia:!0,title:this.post.title,description:this.post.description,imageTitle:this.post.imageTitle,imageAltTag:this.post.imageAltTag}).then(()=>{}).catch(e=>{console.error(`Unable to update attachment with ID ${this.post.id}: ${e}`)})},cancel(){this.value=this.post.value,this.showEditTitle=!1,this.showEditDescription=!1,this.showEditImageTitle=!1,this.showEditImageAltTag=!1},editTitle(){this.showEditTitle=!0},editDescription(){this.showEditDescription=!0},editImageTitle(){this.showEditImageTitle=!0},editImageAlt(){this.showEditImageAltTag=!0},truncate:z,updatePostTitle(e,l){const p=document.getElementById(`post-${e}`);if(!p)return;const g=p.getElementsByClassName("title")[0].getElementsByTagName("a")[0];if(!g)return;const t=g.getElementsByTagName("span")[0];g.innerText=l,g.prepend(t)},updateInspectionResult(e){const{inspectionResult:l,inspectionResultLoading:p}=e;this.inspectionResult=l,this.inspectionResultLoading=p}},mounted(){this.postId=this.post.id,this.columnName=this.post.columnName,this.value=this.post.value,this.imageTitle=this.post.imageTitle,this.imageAltTag=this.post.imageAltTag,this.isSpecialPage=this.post.isSpecialPage,this.title=this.post.title||this.post.defaultTitle,this.titleParsed=this.post.titleParsed,this.postDescription=this.post.description||this.post.defaultDescription,this.descriptionParsed=this.post.descriptionParsed,this.inspectionResult=this.post.inspectionResult,this.inspectionResultLoading=this.post.inspectionResultLoading,this.post.reload&&this.save(),window.aioseoBus.$on("updateInspectionResult"+this.postId,this.updateInspectionResult)},beforeUnmount(){window.aioseoBus.$off("updateInspectionResult"+this.postId,this.updateInspectionResult)},async created(){this.showTruSeo=tt()}},gt={key:0,class:"edit-row scores"},ft={class:"edit-row edit-title"},wt={key:0},vt=i("strong",null,":",-1),Tt={key:1,class:"edit-row"},yt={class:"edit-row edit-description"},Ct=["id"],kt=i("strong",null,":",-1),bt={key:2,class:"edit-row"},It={class:"edit-row edit-image-title"},Et=["id"],St=i("strong",null,":",-1),Dt={key:3,class:"edit-row"},Pt={class:"edit-row edit-image-alt"},At=["id"],Vt=i("strong",null,":",-1),xt={key:4,class:"edit-row"};function Lt(e,l,p,g,t,o){var D,P;const f=_("index-status"),v=_("svg-headline-analyzer"),T=_("core-score-button"),w=_("core-tooltip"),k=_("svg-aioseo-logo-gear"),I=_("svg-pencil"),E=_("core-html-tags-editor"),y=_("base-button");return n(),m("div",{class:x(["aioseo-details-column",{editing:t.showEditTitle||t.showEditDescription||t.showEditImageTitle||t.showEditImageAltTag}])},[i("div",null,[e.$root._data.screen.base==="edit"&&!t.isSpecialPage?(n(),m("div",gt,[o.showIndexStatus?(n(),h(f,{key:0,result:(D=t.inspectionResult)==null?void 0:D.indexStatusResult,"result-link":(P=t.inspectionResult)==null?void 0:P.inspectionResultLink,loading:t.inspectionResultLoading,viewable:p.post.isPostVisible,"tooltip-offset":"-150px,0"},null,8,["result","result-link","loading","viewable"])):a("",!0),g.optionsStore.options.advanced.headlineAnalyzer?(n(),h(w,{key:1,type:"action"},{tooltip:r(()=>[c(s(t.strings.headlineScore),1)]),default:r(()=>[d(T,{score:p.post.headlineScore,postId:t.postId},{icon:r(()=>[d(v)]),_:1},8,["score","postId"])]),_:1})):a("",!0),t.showTruSeo&&t.allowed("aioseo_page_analysis")?(n(),h(w,{key:2,type:"action"},{tooltip:r(()=>[c(s(t.strings.truSeoScore),1)]),default:r(()=>[d(T,{score:p.post.value,postId:t.postId},{icon:r(()=>[d(k)]),_:1},8,["score","postId"])]),_:1})):a("",!0)])):a("",!0),i("div",null,[t.allowed("aioseo_page_general_settings")?(n(),h(w,{key:0,class:"aioseo-details-column__tooltip",disabled:t.showEditTitle},{tooltip:r(()=>[i("strong",null,s(t.strings.title)+":",1),c(" "+s(t.titleParsed),1)]),default:r(()=>[i("div",ft,[i("strong",null,s(t.strings.title),1),t.showEditTitle?a("",!0):(n(),m("span",wt,[vt,c(" "+s(o.truncate(t.titleParsed,100)),1)])),t.showEditTitle?a("",!0):(n(),h(I,{key:1,class:"pencil-icon",onClick:u(o.editTitle,["prevent"])},null,8,["onClick"]))])]),_:1},8,["disabled"])):a("",!0)]),t.showEditTitle?(n(),m("div",Tt,[d(E,{modelValue:t.title,"onUpdate:modelValue":l[0]||(l[0]=C=>t.title=C),"line-numbers":!1,single:"","tags-context":"postTitle",defaultMenuOrientation:"bottom",tagsDescription:"","default-tags":["post_title"]},null,8,["modelValue"]),d(y,{type:"gray",size:"small",onClick:u(o.cancel,["prevent"])},{default:r(()=>[c(s(t.strings.discardChanges),1)]),_:1},8,["onClick"]),d(y,{type:"blue",size:"small",onClick:u(o.save,["prevent"])},{default:r(()=>[c(s(t.strings.saveChanges),1)]),_:1},8,["onClick"])])):a("",!0),i("div",null,[t.allowed("aioseo_page_general_settings")?(n(),h(w,{key:0,class:"aioseo-details-column__tooltip",disabled:t.showEditDescription},{tooltip:r(()=>[i("strong",null,s(t.strings.description)+":",1),c(" "+s(o.truncate(t.descriptionParsed)),1)]),default:r(()=>[i("div",yt,[i("strong",null,s(t.strings.description),1),t.showEditDescription?a("",!0):(n(),m("span",{key:0,id:`aioseo-${t.columnName}-${t.postId}-value`},[kt,c(" "+s(o.truncate(t.descriptionParsed)),1)],8,Ct)),t.showEditDescription?a("",!0):(n(),h(I,{key:1,class:"pencil-icon",onClick:u(o.editDescription,["prevent"])},null,8,["onClick"]))])]),_:1},8,["disabled"])):a("",!0)]),t.showEditDescription?(n(),m("div",bt,[d(E,{modelValue:t.postDescription,"onUpdate:modelValue":l[1]||(l[1]=C=>t.postDescription=C),"line-numbers":!1,"tags-context":"postDescription",defaultMenuOrientation:"bottom",tagsDescription:"","default-tags":["post_excerpt"]},null,8,["modelValue"]),d(y,{type:"gray",size:"small",onClick:u(o.cancel,["prevent"])},{default:r(()=>[c(s(t.strings.discardChanges),1)]),_:1},8,["onClick"]),d(y,{type:"blue",size:"small",onClick:u(o.save,["prevent"])},{default:r(()=>[c(s(t.strings.saveChanges),1)]),_:1},8,["onClick"])])):a("",!0),Q(e.$slots,"default"),i("div",null,[e.$root._data.screen.base==="upload"&&p.post.showMedia?(n(),h(w,{key:0,class:"aioseo-details-column__tooltip",disabled:t.showEditImageTitle},{tooltip:r(()=>[i("strong",null,s(t.strings.imageTitle)+":",1),c(" "+s(t.imageTitle),1)]),default:r(()=>[i("div",It,[i("strong",null,s(t.strings.imageTitle),1),t.showEditImageTitle?a("",!0):(n(),m("span",{key:0,id:`aioseo-${t.columnName}-${t.postId}-value`},[St,c(" "+s(t.imageTitle),1)],8,Et)),t.showEditImageTitle?a("",!0):(n(),h(I,{key:1,class:"pencil-icon",onClick:u(o.editImageTitle,["prevent"])},null,8,["onClick"]))])]),_:1},8,["disabled"])):a("",!0)]),t.showEditImageTitle?(n(),m("div",Dt,[d(E,{modelValue:t.imageTitle,"onUpdate:modelValue":l[2]||(l[2]=C=>t.imageTitle=C),"line-numbers":!1,single:"","tags-context":"attachmentTitle",defaultMenuOrientation:"bottom",tagsDescription:"","default-tags":["image_title"]},null,8,["modelValue"]),d(y,{type:"gray",size:"small",onClick:u(o.cancel,["prevent"])},{default:r(()=>[c(s(t.strings.discardChanges),1)]),_:1},8,["onClick"]),d(y,{type:"blue",size:"small",onClick:u(o.saveImage,["prevent"])},{default:r(()=>[c(s(t.strings.saveChanges),1)]),_:1},8,["onClick"])])):a("",!0),i("div",null,[e.$root._data.screen.base==="upload"&&p.post.showMedia?(n(),h(w,{key:0,class:"aioseo-details-column__tooltip",disabled:t.showEditImageAltTag},{tooltip:r(()=>[i("strong",null,s(t.strings.imageAltTag)+":",1),c(" "+s(t.imageAltTag),1)]),default:r(()=>[i("div",Pt,[i("strong",null,s(t.strings.imageAltTag),1),t.showEditImageAltTag?a("",!0):(n(),m("span",{key:0,id:`aioseo-${t.columnName}-${t.postId}-value`},[Vt,c(" "+s(t.imageAltTag),1)],8,At)),t.showEditImageAltTag?a("",!0):(n(),h(I,{key:1,class:"pencil-icon",onClick:u(o.editImageAlt,["prevent"])},null,8,["onClick"]))])]),_:1},8,["disabled"])):a("",!0)]),t.showEditImageAltTag?(n(),m("div",xt,[d(E,{modelValue:t.imageAltTag,"onUpdate:modelValue":l[3]||(l[3]=C=>t.imageAltTag=C),"line-numbers":!1,single:"","tags-context":"attachmentDescription",defaultMenuOrientation:"bottom",tagsDescription:"","default-tags":["alt_tag"]},null,8,["modelValue"]),d(y,{type:"gray",size:"small",onClick:u(o.cancel,["prevent"])},{default:r(()=>[c(s(t.strings.discardChanges),1)]),_:1},8,["onClick"]),d(y,{type:"blue",size:"small",onClick:u(o.saveImage,["prevent"])},{default:r(()=>[c(s(t.strings.saveChanges),1)]),_:1},8,["onClick"])])):a("",!0)])],2)}const Rt=b(_t,[["render",Lt]]),Nt={components:{CorePostColumn:Rt},props:{post:Object}};function zt(e,l,p,g,t,o){const f=_("core-post-column");return n(),h(f,{post:p.post},null,8,["post"])}const V=b(Nt,[["render",zt]]),Mt={components:{PostColumn:V,PostColumnLite:V},props:{post:Object}},Bt={class:"aioseo-app"};function Ut(e,l,p,g,t,o){const f=_("PostColumn"),v=_("PostColumnLite");return n(),m("div",Bt,[e.$isPro?(n(),h(f,{key:0,post:p.post},null,8,["post"])):a("",!0),e.$isPro?a("",!0):(n(),h(v,{key:1,post:p.post},null,8,["post"]))])}const Ot=b(Mt,[["render",Ut]]);const Ht={setup(){const{strings:e}=M();return{composableStrings:e}},components:{BaseButton:U,CoreHtmlTagsEditor:H,CoreTooltip:j,SvgPencil:O},mixins:[B],props:{term:Object,terms:Array,index:Number},data(){return{termId:null,columnName:null,title:null,titleParsed:null,termDescription:null,descriptionParsed:null,showEditTitle:!1,showEditDescription:!1,showTruSeo:!1,strings:N(this.composableStrings,{title:this.$t.__("Title",this.$td),description:this.$t.__("Description",this.$td),saveChanges:this.$t.__("Save Changes",this.$td),discardChanges:this.$t.__("Discard Changes",this.$td)})}},methods:{save(){this.showEditTitle=!1,this.showEditDescription=!1,this.term.title=this.title,this.term.description=this.termDescription,S.post(this.$links.restUrl("termscreen")).send({termId:this.term.id,title:this.term.title,description:this.term.description}).then(e=>{this.titleParsed=e.body.title,this.descriptionParsed=e.body.description,this.term.titleParsed=e.body.title,this.term.descriptionParsed=e.body.description}).catch(e=>{console.error(`Unable to update term with ID ${this.term.id}: ${e}`)})},cancel(){this.showEditTitle=!1,this.showEditDescription=!1},editTitle(){this.showEditTitle=!0},editDescription(){this.showEditDescription=!0},truncate:z},mounted(){this.termId=this.term.id,this.columnName=this.term.columnName,this.title=this.term.title,this.titleParsed=this.term.titleParsed,this.termDescription=this.term.description,this.descriptionParsed=this.term.descriptionParsed,this.term.reload&&this.save()},async created(){this.showTruSeo=et()}},jt={class:"aioseo-app"},Zt={class:"edit-row edit-title"},qt={key:0},Ft=i("strong",null,":",-1),Gt={key:0,class:"edit-row"},Qt={class:"edit-row edit-description"},Xt={key:0},Yt=i("strong",null,":",-1),Jt={key:1,class:"edit-row"};function Kt(e,l,p,g,t,o){const f=_("svg-pencil"),v=_("core-tooltip"),T=_("core-html-tags-editor"),w=_("base-button");return n(),m("div",jt,[i("div",{class:x(["aioseo-details-column",{editing:t.showEditTitle||t.showEditDescription}])},[i("div",null,[i("div",null,[d(v,{class:"aioseo-details-column__tooltip"},{tooltip:r(()=>[i("strong",null,s(t.strings.title)+":",1),c(" "+s(t.titleParsed),1)]),default:r(()=>[i("div",Zt,[i("strong",null,s(t.strings.title),1),t.showEditTitle?a("",!0):(n(),m("span",qt,[Ft,c(" "+s(o.truncate(t.titleParsed,100)),1)])),t.showEditTitle?a("",!0):(n(),h(f,{key:1,class:"pencil-icon",onClick:u(o.editTitle,["prevent"])},null,8,["onClick"]))])]),_:1})]),t.showEditTitle?(n(),m("div",Gt,[d(T,{modelValue:t.title,"onUpdate:modelValue":l[0]||(l[0]=k=>t.title=k),"line-numbers":!1,single:"","tags-context":"taxonomyTitle",defaultMenuOrientation:"bottom",tagsDescription:"","default-tags":["taxonomy_title"]},null,8,["modelValue"]),d(w,{type:"gray",size:"small",onClick:u(o.cancel,["prevent"])},{default:r(()=>[c(s(t.strings.discardChanges),1)]),_:1},8,["onClick"]),d(w,{type:"blue",size:"small",onClick:u(o.save,["prevent"])},{default:r(()=>[c(s(t.strings.saveChanges),1)]),_:1},8,["onClick"])])):a("",!0),i("div",null,[d(v,{class:"aioseo-details-column__tooltip"},{tooltip:r(()=>[i("strong",null,s(t.strings.description)+":",1),c(" "+s(t.descriptionParsed),1)]),default:r(()=>[i("div",Qt,[i("strong",null,s(t.strings.description),1),t.showEditDescription?a("",!0):(n(),m("span",Xt,[Yt,c(" "+s(o.truncate(t.descriptionParsed)),1)])),t.showEditDescription?a("",!0):(n(),h(f,{key:1,class:"pencil-icon",onClick:u(o.editDescription,["prevent"])},null,8,["onClick"]))])]),_:1})]),t.showEditDescription?(n(),m("div",Jt,[d(T,{modelValue:t.termDescription,"onUpdate:modelValue":l[1]||(l[1]=k=>t.termDescription=k),"line-numbers":!1,"tags-context":"taxonomyDescription",defaultMenuOrientation:"bottom",tagsDescription:"","default-tags":["taxonomy_description"]},null,8,["modelValue"]),d(w,{type:"gray",size:"small",onClick:u(o.cancel,["prevent"])},{default:r(()=>[c(s(t.strings.discardChanges),1)]),_:1},8,["onClick"]),d(w,{type:"blue",size:"small",onClick:u(o.save,["prevent"])},{default:r(()=>[c(s(t.strings.saveChanges),1)]),_:1},8,["onClick"])])):a("",!0)])],2)])}const Wt=b(Ht,[["render",Kt]]),Z=e=>(e=X(e),e=Y(e),e=J(e),$(e),e.config.globalProperties.$truSeo=new st,e),q=e=>{const l=document.getElementById(e);l!=null&&l.__vue_app__&&l.__vue_app__.unmount()},F=e=>{q(`${e.columnName}-${e.id}`),Z(L({name:"Standalone/PostsTable/"+e.id,data(){return{screen:window.aioseo.screen}},render:()=>R(Ot)},{post:e})).mount(`#${e.columnName}-${e.id}`)};window.aioseo.posts&&window.aioseo.posts.forEach(e=>{F(e)});const G=e=>{q(`${e.columnName}-${e.id}`),Z(L({name:"Standalone/TermsTable/"+e.id,data(){return{screen:window.aioseo.screen}},render:()=>R(Wt)},{term:e})).mount(`#${e.columnName}-${e.id}`)};window.aioseo.terms&&window.aioseo.posts.length===0&&window.aioseo.terms.forEach(e=>{G(e)});(function(e){e(document).on("ajaxComplete",(l,p,g)=>{const t=new URLSearchParams(g.data),o=t==null?void 0:t.get("action");if(!(!t||!o)){if(o==="inline-save"){const{post_ID:f}=Object.fromEntries(t.entries()),v=window.aioseo.posts.find(T=>T.id===parseInt(f));F({...v,reload:!0})}if(o==="inline-save-tax"){const{tax_ID:f}=Object.fromEntries(t.entries()),v=window.aioseo.terms.find(T=>T.id===parseInt(f));G({...v,reload:!0})}}})})(window.jQuery);
