document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('detect').addEventListener('click', function() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      var tab = tabs[0];
      chrome.runtime.sendMessage({action: "detect", url: tab.url}, function(response) {
        var resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = '';
        
        if (response) {
          for (let category in response) {
            if (response[category].length > 0) {
              let categoryDiv = document.createElement('div');
              categoryDiv.innerHTML = `<h3>${capitalizeCategory(category)}</h3>`;
              
              for (let issue of response[category]) {
                let p = document.createElement('p');
                // 特殊处理点击劫持的PoC链接
                if (category === 'clickjackingIssues' && issue.poc) {
                  p.innerHTML = `${issue.message} <a href="${issue.poc}" target="_blank">[验证PoC]</a>`;
                } else {
                  p.textContent = typeof issue === 'object' ? issue.message : issue;
                }
                categoryDiv.appendChild(p);
              }
              
              resultsDiv.appendChild(categoryDiv);
            }
          }
        } else {
          resultsDiv.textContent = '未发现漏洞或发生错误。';
        }
      });
    });
  });
});

function capitalizeCategory(category) {
  return category.replace(/([A-Z])/g, ' $1').trim().replace(/^\w/, c => c.toUpperCase());
}
