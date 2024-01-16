import{a as U}from"./allowed.1a0ffdc5.js";import{n as S}from"./isArrayLikeObject.ab8f4241.js";import{c as w}from"./news-sitemap.1ec2e03a.js";import{C as y}from"./GettingStarted.770b9718.js";import{C as O}from"./Index.18716c31.js";import{G as A,a as I}from"./Row.dbbe567c.js";import{S as v}from"./Book.fe43e5fa.js";import{x as o,c as _,k as c,b as g,l as e,a as i,C as r,o as n,D as d,t as a,F as x,L as E}from"./vue.runtime.esm-bundler.4a881941.js";import{_ as P}from"./_plugin-vue_export-helper.abeb2ae0.js";import"./links.125d59c9.js";import"./default-i18n.3881921e.js";import"./Caret.02d7c74a.js";import"./Rocket.b68bcb6e.js";import"./index.e978df4e.js";import"./constants.238e5b7b.js";const D={components:{CoreGettingStarted:y,Cta:O,GridColumn:A,GridRow:I,SvgBook:v},data(){return{allowed:U,ctaImg:w,strings:{cta:{title:this.$t.sprintf(this.$t.__("Get %1$s %2$s and Unlock all the Powerful Features",this.$td),"AIOSEO","Pro"),header:this.$t.sprintf(this.$t.__("Get %1$s %2$s and Unlock all the Powerful Features.",this.$td),"AIOSEO","Pro"),button:this.$t.sprintf(this.$t.__("Upgrade to %1$s Today",this.$td),"Pro")},videos:{title:this.$t.__("Video Tutorials",this.$td),linkText:this.$t.__("View all video tutorials",this.$td),linkUrl:"https://changeme"},documentation:{title:this.$t.sprintf(this.$t.__("%1$s Documentation",this.$td),"AIOSEO"),linkText:this.$t.__("See our full documentation",this.$td),linkUrl:this.$links.getDocUrl("home")}},videos:{video1:{title:this.$t.__("Basic Guide to Google Analytics",this.$td),url:"https://changeme"},video2:{title:this.$t.__("Basic Guide to Google Search Console",this.$td),url:"https://changeme"},video3:{title:this.$t.__("Best Practices for Domains and URLs",this.$td),url:"https://changeme"},video4:{title:this.$t.__("How to Control Search Results",this.$td),url:"https://changeme"},video5:{title:this.$t.sprintf(this.$t.__("Installing %1$s %2$s",this.$td),"AIOSEO","Pro"),url:"https://changeme"},video6:{title:this.$t.__("Optimizing your Content Headings",this.$td),url:"https://changeme"}},docs:{doc1:{title:"How do I get Google to show sitelinks for my site?",url:this.$links.getDocUrl("showSitelinks")},doc2:{title:"How do I use your API code examples?",url:this.$links.getDocUrl("apiCodeExamples")},doc3:{title:"What are media attachments and should I submit them to search engines?",url:this.$links.getDocUrl("whatAreMediaAttachments")},doc4:{title:"When to use NOINDEX or the robots.txt?",url:this.$links.getDocUrl("whenToUseNoindex")},doc5:{title:"How do I troubleshoot issues with AIOSEO?",url:this.$links.getDocUrl("troubleshootIssues")},doc6:{title:"How does the import process for SEO data work?",url:this.$links.getDocUrl("importProcessSeoData")},doc7:{title:"Installation instructions for AIOSEO Pro",url:this.$links.getDocUrl("installAioseoPro")},doc8:{title:"What are the minimum requirements for All in One SEO?",url:this.$links.getDocUrl("minimumRequirements")}}}},computed:{upgradeToday(){return this.$t.sprintf(this.$t.__("%1$s %2$s comes with many additional features to help take your site's SEO to the next level!",this.$td),"AIOSEO","Pro")}},methods:{getAssetUrl:S}},b={class:"aioseo-getting-started"},G=["src"],C={class:"aioseo-getting-started-documentation"},T=["href"],L={class:"d-flex"},B=["href"];function N(s,H,R,V,t,u){const p=o("core-getting-started"),f=o("cta"),l=o("grid-column"),h=o("grid-row"),$=o("svg-book");return n(),_("div",b,[t.allowed("aioseo_setup_wizard")?(n(),c(p,{key:0,"disable-close":""})):g("",!0),s.$isPro?g("",!0):(n(),c(f,{key:1,class:"aioseo-getting-started-cta",type:2,floating:!1,"button-text":t.strings.cta.button,"cta-link":s.$links.utmUrl("getting-started","main-cta"),"learn-more-link":s.$links.getUpsellUrl("getting-started","main-cta",s.$isPro?"pricing":"liteUpgrade"),"feature-list":s.$constants.UPSELL_FEATURE_LIST,showLink:!1},{"header-text":e(()=>[d(a(t.strings.cta.header),1)]),description:e(()=>[d(a(u.upgradeToday),1)]),"featured-image":e(()=>[i("img",{alt:"Getting Started with AIOSEO",src:u.getAssetUrl(t.ctaImg)},null,8,G)]),_:1},8,["button-text","cta-link","learn-more-link","feature-list"])),i("div",C,[r(h,{class:"header"},{default:e(()=>[r(l,{class:"header-title",sm:"6",md:"6"},{default:e(()=>[d(a(t.strings.documentation.title),1)]),_:1}),r(l,{sm:"6",md:"6",class:"header-link"},{default:e(()=>[i("a",{href:t.strings.documentation.linkUrl,target:"_blank"},a(t.strings.documentation.linkText)+" → ",9,T)]),_:1})]),_:1}),r(h,{class:"docs"},{default:e(()=>[(n(!0),_(x,null,E(t.docs,(m,k)=>(n(),c(l,{class:"doc",key:k,sm:"12",md:"6"},{default:e(()=>[i("div",L,[r($),i("a",{href:m.url,target:"_blank"},a(m.title),9,B)])]),_:2},1024))),128))]),_:1})])])}const ot=P(D,[["render",N]]);export{ot as default};
