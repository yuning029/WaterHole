chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  if (request.action === "detect") {
    detectVulnerabilities(request.url).then(function(results) {
      sendResponse(results);
    });
    return true; // 表示异步响应
  }
});

async function detectVulnerabilities(url) {
  let results = {
    headerIssues: [],
    httpMethodIssues: [],
    errorInfoIssues: [],
    robotsIssues: [],
    sitemapsIssues: [],
    unauthorizedAccessIssues: [],
    clickjackingIssues: []
  };

  try {
    let headersFuture = getHeaders(url);
    let optionsFuture = getOptionsVuln(url);
    let errorInfoFuture = getErrorInfoVuln(url);
    let robotsFuture = checkRobotsTxt(url);
    let sitemapsFuture = checkSitemaps(url);
    let unauthorizedAccessFuture = checkUnauthorizedAccess(url);

    await Promise.all([headersFuture, optionsFuture, errorInfoFuture, robotsFuture, sitemapsFuture, unauthorizedAccessFuture]);

    let headers = await headersFuture;
    let headerVulns = getHeadersVuln(headers);
    results.headerIssues = headerVulns.filter(v => !v.includes('X-Frame-Options'));
    
    // 增强点击劫持检测
    if (headerVulns.some(v => v.includes('X-Frame-Options'))) {
      const pocUrl = chrome.runtime.getURL(`Clickjacking_PoC.html?url=${encodeURIComponent(url)}`);
      results.clickjackingIssues.push({
        message: "(点击劫持) X-Frame-Options 头缺失，可能存在点击劫持漏洞",
        poc: pocUrl
      });
    }

    results.httpMethodIssues = await optionsFuture;
    results.errorInfoIssues = await errorInfoFuture;
    results.robotsIssues = await robotsFuture;
    results.sitemapsIssues = await sitemapsFuture;
    results.unauthorizedAccessIssues = await unauthorizedAccessFuture;
  } catch (error) {
    console.error(`检测出错: ${error}`);
    results.generalError = [error.message];
  }

  return results;
}

async function getHeaders(url) {
  try {
    let response = await fetch(url, {
      method: 'GET',
      mode: 'cors',
      credentials: 'include',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
      }
    });
    if (response.ok) {
      let headers = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });
      return headers;
    }
    return null;
  } catch (error) {
    console.error(`获取响应头失败: ${error}`);
    return null;
  }
}

function getHeadersVuln(headers) {
  if (!headers) {
    return ["无法获取响应头"];
  }

  let result = [];

  const vulnHeaders = {
    'X-Frame-Options': '.*',
    'Content-Security-Policy': '.*',
    'Set-Cookie': '.*'
  };

  for (let vulnHeader in vulnHeaders) {
    if (!(vulnHeader in headers)) {
      if (vulnHeader !== 'Set-Cookie') {
        result.push(`(响应头缺失) ${vulnHeader} 头缺失`);
      }
    } else if (vulnHeader === 'Set-Cookie') {
      let cookieHeaders = headers[vulnHeader].split(/,\s*/);
      for (let cookieHeader of cookieHeaders) {
        let cookieParts = cookieHeader.split(/;\s*/);
        let hasHttpOnly = false;
        let hasSecure = false;
        for (let part of cookieParts) {
          if (part.trim().toLowerCase() === 'httponly') {
            hasHttpOnly = true;
          }
          if (part.trim().toLowerCase() === 'secure') {
            hasSecure = true;
          }
        }
        if (!hasHttpOnly) {
          result.push(`(响应头缺失) Set-Cookie 中 HttpOnly 属性缺失 for ${cookieParts[0]}`);
        }
        if (!hasSecure) {
          result.push(`(响应头缺失) Set-Cookie 中 Secure 属性缺失 for ${cookieParts[0]}`);
        }
      }
    }
  }

  const vulnHeaders2 = {
    'Server': '(Microsoft-IIS/[\d\.]+)|Nginx/[\d\.]+|Servlet/[\d\. ]+jsp/[\d\. ]+|Apache/[\d\. ]',
    'X-Powered-By': '(ASP.NET)|(PHP/[\d\. ]+)'
  };

  for (let vulnHeader2 in vulnHeaders2) {
    if (vulnHeader2 in headers) {
      let pattern = new RegExp(vulnHeaders2[vulnHeader2], 'i');
      if (pattern.test(headers[vulnHeader2])) {
        result.push(`(信息泄露) ${vulnHeader2}: ${headers[vulnHeader2]}`);
      }
    }
  }

  return result;
}

async function getOptionsVuln(url) {
  let result = [];
  try {
    let optionsResponse = await fetch(url, {
      method: 'OPTIONS',
      mode: 'cors',
      credentials: 'include'
    });
    
    if (optionsResponse.ok) {
      const allowMethods = optionsResponse.headers.get('Allow') || 
                          optionsResponse.headers.get('Access-Control-Allow-Methods');
      if (allowMethods) {
        result.push(`(不安全HTTP方法) 允许的HTTP方法: ${allowMethods}`);
      } else {
        result.push("(HTTP方法检测) 服务器响应OPTIONS请求但未返回允许的方法列表");
      }
    }
  } catch (error) {
    console.error(`检查OPTIONS方法失败: ${error}`);
  }
  return result;
}

async function getErrorInfoVuln(url) {
  let result = [];
  try {
    let errorUrl = new URL(url); 
    errorUrl.pathname = errorUrl.pathname.replace(/\/$/, '') + '/esssdad';
    let response = await fetch(errorUrl.toString(), {
      method: 'GET',
      mode: 'cors',
      credentials: 'include'
    });
    if ([404, 500, 403].includes(response.status)) {
      let text = await response.text();
      let paths = text.match(/[cdexf]:\\[\w]+\\[\w]+[\\\w\.]+/gi);
      if (paths) {
        paths = [...new Set(paths)];
        paths.forEach(path => {
          result.push(`(绝对路径泄露) ${errorUrl} ${path}`);
        });
      }
      let apacheVersions = text.match(/Apache Tomcat\/[\d\.]+/gi);
      if (apacheVersions) {
        apacheVersions = [...new Set(apacheVersions)];
        apacheVersions.forEach(version => {
          result.push(`(Apache 版本泄露) ${errorUrl} ${version}`);
        });
      }
      if (/The server understood the/.test(text)) {
        result.push(`(Weblogic 默认报错页面) ${errorUrl}`);
      }
    }
  } catch (error) {
    console.error(`检查错误信息失败: ${error}`);
  }
  return result;
}

async function checkRobotsTxt(url) {
  let result = [];
  try {
    let robotsUrl = new URL(url);
    robotsUrl.pathname = '/robots.txt';
    let response = await fetch(robotsUrl.toString(), {
      method: 'GET',
      mode: 'cors',
      credentials: 'include'
    });
    if (response.ok) {
      let text = await response.text();
      if (text.includes('Disallow: /admin') || text.includes('Disallow: /login')) {
        result.push("robots.txt 可能暴露敏感目录");
      }
      if (text.includes('Allow: /')) {
        result.push("robots.txt 允许全站爬取");
      }
    } else {
      result.push("未找到 robots.txt 文件");
    }
  } catch (error) {
    result.push(`检查 robots.txt 失败: ${error.message}`);
  }
  return result;
}

async function checkSitemaps(url) {
  let result = [];
  try {
    let sitemapsUrl = new URL(url);
    sitemapsUrl.pathname = '/sitemaps.xml';
    let response = await fetch(sitemapsUrl.toString(), {
      method: 'GET',
      mode: 'cors',
      credentials: 'include'
    });
    if (response.ok) {
      result.push("找到 sitemaps.xml");
    } else {
      result.push("未找到 sitemaps.xml 文件");
    }
  } catch (error) {
    result.push(`检查 sitemaps.xml 失败: ${error.message}`);
  }
  return result;
}

async function checkUnauthorizedAccess(url) {
  let result = [];
  try {
    let response = await fetch(url, {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit', // 去掉 Cookie
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'
      }
    });

    if (response.ok) {
      result.push(`(未授权访问) 成功访问 ${url} 未经授权`);
    } else if (response.status === 401 || response.status === 403) {
      result.push(`(授权正常) ${url} 需要授权`);
    } else {
      result.push(`(其他状态) ${url} 返回状态码 ${response.status}`);
    }
  } catch (error) {
    console.error(`检查未授权访问失败: ${error}`);
    result.push(`检查未授权访问失败: ${error.message}`);
  }
  return result;
}
