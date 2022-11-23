# Projeto Final: Desenvolvimento de um DApp

DApps vem de *decentralized applications*, ou seja, aplicativos descentralizados. Um DApp é basicamente um aplicativo em blockchain que funciona numa rede interconectada e pode recompensar usuários com tokens, ou proporcionar novas experiências digitais, ou trabalhar colaborativamente em prol do funcionamento e sustentabilidade do seu sistema descentralizado. Eles funcionam com contratos inteligentes independentes.

A maioria do *front-end* dos DApps usa a mesma tecnologia de um *app* da _web_ convencional para renderizar a página, a diferença é que em vez de uma API se conectar a um banco de dados, é um *smart contract* conectado a um blockchain. 

A arquitetura de um Dapp é bastante simples:

```DApp: Front End → Smart Contract → Blockchain```

Basicamente um DApp é um *app* armazenado em uma rede blockchain, onde o *smart contract* é o que permite que ele se conecte ao blockchain.


## Descrição

O objetivo deste projeto é o desenvolvimento de um DApp completo, com temática livre, incluindo toda a lógica da aplicação, contida no formato de _smart contracts_ que serão implantados na rede Ethereum Ropsten, e o *front-end* centralizado que irá se comunicar com um nó Ethereum através da biblioteca **web3.js**.

Para o *front-end* utilize quaisquer tecnologia que julgue interessante. Os principais *frameworks*/bibliotecas de desenvolvimento *front-end* hoje em dia são o Vue.js, o Angular, o React e o Svelte. Mas se quiser usar somente JavaScript nativo (_vanilla_), fique a vontade!

Para o desenvolvimento dos contratos inteligentes, utilize a linguagem de programação **Solidity**, em qualquer uma de suas versões. O *deploy* final deverá obrigatoriamente ser na rede Sepolia. Recomendo fortemente o uso do [Remix](https://remix.ethereum.org/) para codificação, compilação e _deploy_ dos _smart contracts_. Caso prefira, vocë pode usar um blockchain Ethereum local na sua máquina, utilizando, por exemplo, o Ganache. Se não quiser, pode implantar direto na rede Sepolia.


## Metodologia e Avaliação

O projeto final deve ser realizado **individualmente ou em dupla**. O projeto deverá ser apresentado, por todos os membros do grupo, em data e horário pré-definido, que serão sorteados entre os grupos existentes.

Ainda precisarão ser entregues:

- O *link* para o GitHub Pages hospedando o *front-end* da sua aplicação. Caso sua aplicação exija tecnologias não compatíveis com a hospedagem do GitHub, pode executar em um servidor local.
- O endereço de contrato da sua aplicação na rede Sepolia.
- O código do seu contrato e demais artefatos da sua aplicação, devidamente comentado (GitHub).

O cronograma será:

- até 05/12/2022 : **[Obrigatório]** Apresentar a proposta de tema e esboço/protótipo do funcionamento da aplicação para o professor.
- 30/11/2022 16h50min : **[Opcional]** Acompanhamento do andamento do projeto em sala de aula.
- 05/12/2022 16h50min : **[Opcional]** Acompanhamento do andamento do projeto em sala de aula.
- 07/12/2022 16h50min : **[Opcional]** Acompanhamento do andamento do projeto em sala de aula.
- **[Obrigatório]** Apresentar o projeto final ao professor em data e horário pré-definido:
    - 12/12/2022 16h50min : 1º dia de apresentações.
    - 14/12/2022 16h50min : 2º dia de apresentações.



Alguns critérios utilizados na avaliação, porém não restritos a estes, são:

- Criatividade e exclusividade do escopo da aplicação
    - *evitar utilizar aplicações já amplamente exploradas e disponíveis na internet.*
- Complexidade e magnitude da aplicação desenvolvida
    - *a apresentação da proposta do tema ao professor irá filtrar aplicações que não atendem esse requisito*
- Qualidade dos contrato(s) inteligente(s) utilizado(s)
    - *utilizar linguagem Solidity e explorar seus recursos*
- Qualidade do *front-end* desenvolvido
    - *usabilidade e experiência do usuário*

**Aplicações resultantes de plágios serão desconsideradas e não serão avaliadas.**

## Código Base

Consulte o projeto de desenvolvimento do DApp da Rifa para tomar como base: 

[Repositório do DApp](https://github.com/danilocurvelo/dapp-rifa)

[DApp Rifa em produção](https://danilocurvelo.github.io/dapp-rifa/)

Sugestão de código *javascript* para detectar o objeto web3 injetado no seu navegador para interagir com seu *front-end*:

```javascript
// ENDEREÇO EHTEREUM DO CONTRATO
var contractAddress = "0x5F408b84B13F470C689311d130396E1dd6Db16B4";

// Inicializa o objeto DApp
document.addEventListener("DOMContentLoaded", onDocumentLoad);
function onDocumentLoad() {
  DApp.init();
}

// Nosso objeto DApp que irá armazenar a instância web3
const DApp = {
  web3: null,
  contracts: {},
  account: null,

  init: function () {
    return DApp.initWeb3();
  },

  // Inicializa o provedor web3
  initWeb3: async function () {
    if (typeof window.ethereum !== "undefined") {
      try {
        const accounts = await window.ethereum.request({ // Requisita primeiro acesso ao Metamask
          method: "eth_requestAccounts",
        });
        DApp.account = accounts[0];
        window.ethereum.on('accountsChanged', DApp.updateAccount); // Atualiza se o usuário trcar de conta no Metamaslk
      } catch (error) {
        console.error("Usuário negou acesso ao web3!");
        return;
      }
      DApp.web3 = new Web3(window.ethereum);
    } else {
      console.error("Instalar MetaMask!");
      return;
    }
    return DApp.initContract();
  },

  // Atualiza 'DApp.account' para a conta ativa no Metamask
  updateAccount: async function() {
    DApp.account = (await DApp.web3.eth.getAccounts())[0];
    atualizaInterface();
  },

  // Associa ao endereço do seu contrato
  initContract: async function () {
    DApp.contracts.Contrato = new DApp.web3.eth.Contract(abi, contractAddress);
    return DApp.render();
  },

  // Inicializa a interface HTML com os dados obtidos
  render: async function () {
    inicializaInterface();
  },
};
```
