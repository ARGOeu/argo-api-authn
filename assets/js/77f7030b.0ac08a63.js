"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[953],{1986:(e,r,t)=>{t.r(r),t.d(r,{assets:()=>c,contentTitle:()=>d,default:()=>h,frontMatter:()=>i,metadata:()=>o,toc:()=>l});var s=t(4848),n=t(8453);const i={id:"api_errors",title:"Errors",sidebar_position:7},d="Errors",o={id:"api_errors",title:"Errors",description:"In case of an Error during handling a user\u2019s request, the API responds using the following schema:",source:"@site/docs/api_errors.md",sourceDirName:".",slug:"/api_errors",permalink:"/argo-api-authn/docs/api_errors",draft:!1,unlisted:!1,tags:[],version:"current",sidebarPosition:7,frontMatter:{id:"api_errors",title:"Errors",sidebar_position:7},sidebar:"tutorialSidebar",previous:{title:"Health",permalink:"/argo-api-authn/docs/api_health"},next:{title:"Utility Scripts",permalink:"/argo-api-authn/docs/utility_scripts"}},c={},l=[{value:"Error Codes",id:"error-codes",level:2}];function a(e){const r={code:"code",h1:"h1",h2:"h2",p:"p",pre:"pre",table:"table",tbody:"tbody",td:"td",th:"th",thead:"thead",tr:"tr",...(0,n.R)(),...e.components};return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(r.h1,{id:"errors",children:"Errors"}),"\n",(0,s.jsx)(r.p,{children:"In case of an Error during handling a user\u2019s request, the API responds using the following schema:"}),"\n",(0,s.jsx)(r.pre,{children:(0,s.jsx)(r.code,{className:"language-json",children:'{\n   "error": {\n      "code": 500,\n      "message": "Something bad happened",\n      "status": "INTERNAL"\n   }\n}\n'})}),"\n",(0,s.jsx)(r.h2,{id:"error-codes",children:"Error Codes"}),"\n",(0,s.jsx)(r.p,{children:"The following error codes are the possible errors of all methods"}),"\n",(0,s.jsxs)(r.table,{children:[(0,s.jsx)(r.thead,{children:(0,s.jsxs)(r.tr,{children:[(0,s.jsx)(r.th,{children:"Error"}),(0,s.jsx)(r.th,{children:"Code"}),(0,s.jsx)(r.th,{children:"Status"}),(0,s.jsx)(r.th,{children:"Related Requests"})]})}),(0,s.jsxs)(r.tbody,{children:[(0,s.jsxs)(r.tr,{children:[(0,s.jsx)(r.td,{children:"Invalid JSON"}),(0,s.jsx)(r.td,{children:"400"}),(0,s.jsx)(r.td,{children:"BAD REQUEST"}),(0,s.jsx)(r.td,{children:"Create Service (POST)"})]}),(0,s.jsxs)(r.tr,{children:[(0,s.jsx)(r.td,{children:"Not found"}),(0,s.jsx)(r.td,{children:"404"}),(0,s.jsx)(r.td,{children:"NOT FOUND"}),(0,s.jsx)(r.td,{children:"List One service(GET)"})]}),(0,s.jsxs)(r.tr,{children:[(0,s.jsx)(r.td,{children:"Service already exists"}),(0,s.jsx)(r.td,{children:"409"}),(0,s.jsx)(r.td,{children:"CONFLICT"}),(0,s.jsx)(r.td,{children:"Create Service (POST)"})]}),(0,s.jsxs)(r.tr,{children:[(0,s.jsx)(r.td,{children:"Service Invalid Argument"}),(0,s.jsx)(r.td,{children:"422"}),(0,s.jsx)(r.td,{children:"UNPROCCESABLE ENTITY"}),(0,s.jsx)(r.td,{children:"Create Service (POST)"})]}),(0,s.jsxs)(r.tr,{children:[(0,s.jsx)(r.td,{children:"Server Error"}),(0,s.jsx)(r.td,{children:"500"}),(0,s.jsx)(r.td,{children:"INTERNAL SERVER ERROR"}),(0,s.jsx)(r.td,{children:"ALL"})]})]})]})]})}function h(e={}){const{wrapper:r}={...(0,n.R)(),...e.components};return r?(0,s.jsx)(r,{...e,children:(0,s.jsx)(a,{...e})}):a(e)}},8453:(e,r,t)=>{t.d(r,{R:()=>d,x:()=>o});var s=t(6540);const n={},i=s.createContext(n);function d(e){const r=s.useContext(i);return s.useMemo((function(){return"function"==typeof e?e(r):{...r,...e}}),[r,e])}function o(e){let r;return r=e.disableParentContext?"function"==typeof e.components?e.components(n):e.components||n:d(e.components),s.createElement(i.Provider,{value:r},e.children)}}}]);