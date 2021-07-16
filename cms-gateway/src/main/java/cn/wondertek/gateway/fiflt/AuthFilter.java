package cn.wondertek.gateway.fiflt;


import cn.wondertek.common.constant.Constants;
import cn.wondertek.common.core.domain.R;
import cn.wondertek.gateway.constants.FilterConstant;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import static java.net.URLEncoder.encode;

/**
 * 网关鉴权
 */
@Slf4j
@Component
public class AuthFilter implements GlobalFilter, Ordered {
    public static final String[] restWhiteList = FilterConstant.restWhiteList;
    public static final String[] LoginOrNoLoginRestWhiteList = FilterConstant.LoginOrNoLoginRestWhiteList;
    public static final String[] whiteList =FilterConstant.whiteList;

    @Resource(name = "stringRedisTemplate")
    private ValueOperations<String, String> ops;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String url = exchange.getRequest().getURI().getPath();
        log.info("url:{}", url);


        String token = exchange.getRequest().getHeaders().getFirst(Constants.TOKEN);
        String userName = "";
        String loginName = "";
        String identification = "";
        String mobile = "";
        String userStr = ops.get(Constants.CMS_ACCESS_TOKEN + token);
        if (StringUtils.isNotBlank(userStr)) {
            identification = Constants.IDENTIFICATION_WEB;
        } else if ( (userStr = ops.get(Constants.APP_ACCESS_TOKEN + token)) != null ){
            identification = Constants.IDENTIFICATION_APP;
        } else if ((userStr = ops.get(Constants.WECHAT_ACCESS_TOKEN + token)) != null){
            identification = Constants.IDENTIFICATION_WECHAT;
        }

        JSONObject jo = userStr == null ? new JSONObject() : JSONObject.parseObject(userStr);
        String userId = jo.getString("userId");
        if (Constants.IDENTIFICATION_WEB.equals(identification)) {
            userName = jo.getString("userName");
            loginName = jo.getString("loginName");
            ops.getOperations().expire(Constants.CMS_ACCESS_TOKEN + token, Constants.CMS_ACCESS_TOKEN_EXPIRE, TimeUnit.SECONDS);
            ops.getOperations().expire(Constants.CMS_ACCESS_USERID + userId, Constants.CMS_ACCESS_TOKEN_EXPIRE, TimeUnit.SECONDS);
        } else if (Constants.IDENTIFICATION_APP.equals(identification)) {
            userName = jo.getString("sname");
            loginName = jo.getString("name");
            mobile = jo.getString("mobile");
            ops.getOperations().expire(Constants.APP_ACCESS_TOKEN + token, Constants.APP_ACCESS_TOKEN_EXPIRE, TimeUnit.SECONDS);
            ops.getOperations().expire(Constants.APP_ACCESS_USERID + userId, Constants.APP_ACCESS_TOKEN_EXPIRE, TimeUnit.SECONDS);
        }else if (Constants.IDENTIFICATION_WECHAT.equals(identification)){
            userName = jo.getString("sname");
            loginName = jo.getString("name");
            mobile = jo.getString("mobile");
            ops.getOperations().expire(Constants.WECHAT_ACCESS_TOKEN + token, Constants.WECHAT_ACCESS_TOKEN_EXPIRE, TimeUnit.SECONDS);
            ops.getOperations().expire(Constants.WECHAT_ACCESS_USERID + userId, Constants.WECHAT_ACCESS_TOKEN_EXPIRE, TimeUnit.SECONDS);
        }
        // 设置userId到request里，后续根据userId，获取用户信息
        ServerHttpRequest mutableReq = null;
        try {
            mutableReq = exchange.getRequest().mutate()
                    .header(Constants.CURRENT_ID, userId)
                    .header(Constants.CURRENT_LOGINNAME, URLEncoder.encode(loginName, "UTF-8"))
                    .header(Constants.CURRENT_USERNAME, URLEncoder.encode(userName, "UTF-8"))
                    .header(Constants.IDENTIFICATION, identification)
                    .header(Constants.MOBILE, mobile)
                    .header(Constants.CURRENT_IMG, encode(jo.getString("uploadFile") == null ? "" : jo.getString("uploadFile"), "UTF-8"))
                    .build();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } finally {
            mutableReq = mutableReq == null ? exchange.getRequest().mutate()
                    .build() : mutableReq;
        }
        // 跳过不需要验证的路径
        if (Arrays.asList(whiteList).contains(url)) {
            return chain.filter(exchange);
        }
        Boolean isFlag = true;
        //restfull风格的白名单
        for (String s : restWhiteList) {
            if (url.contains(s)) {
                return chain.filter(exchange);
            }
        }
        //登录和不登录都可以的接口
        for (String s : LoginOrNoLoginRestWhiteList) {
            if (url.contains(s)) {
                isFlag = false;
                break;
            }
        }

        //跳过文件访问路径
        if (url.contains(Constants.FILE_URL)) {
            return chain.filter(exchange);
        }
        //添加测试环境的调试
        String debug = exchange.getRequest().getHeaders().getFirst("debug");
        if ("1".equals(debug)) {
            userId = exchange.getRequest().getHeaders().getFirst(Constants.USER_ID);
            // token为空
            if (StringUtils.isBlank(userId) && isFlag) {
                return setUnauthorizedResponse(exchange, "test env of userId can't null or empty string");
            }
            loginName = exchange.getRequest().getHeaders().getFirst(Constants.LOGIN_NAME);
            // token为空
            if (StringUtils.isBlank(loginName) && isFlag) {
                return setUnauthorizedResponse(exchange, "test env of loginName can't null or empty string");
            }
            ServerWebExchange mutableExchange = exchange.mutate().request(mutableReq).build();
            return chain.filter(mutableExchange);
        } else {
            if (isFlag) {//需要获取token的路径
                // token为空
                if (StringUtils.isBlank(token) && isFlag) {
                    return setUnauthorizedResponse(exchange, "token can't null or empty string");
                }
                String msg = ops.get(Constants.APP_ACCESS_TOKEN_MSG + token);
                if (msg!=null) {
                    ops.getOperations().delete(Constants.APP_ACCESS_TOKEN_MSG + token);
                }
                if (StringUtils.isBlank(userStr)) {
                    return setUnauthorizedResponse(exchange, msg == null ? "token verify error" : msg);
                }
                // 查询token信息
                if (StringUtils.isBlank(userId)) {
                    return setUnauthorizedResponse(exchange, msg == null ? "token verify error" : msg);
                }
                ServerWebExchange mutableExchange = exchange.mutate().request(mutableReq).build();
                return chain.filter(mutableExchange);
            } else {//不需要获取token的路径
                // token为空
                if (StringUtils.isBlank(token)) {
                    return chain.filter(exchange);
                }
                if (StringUtils.isBlank(userStr)) {
                    return chain.filter(exchange);
                }
                ServerWebExchange mutableExchange = exchange.mutate().request(mutableReq).build();
                return chain.filter(mutableExchange);
            }
        }
    }

    private Mono<Void> setUnauthorizedResponse(ServerWebExchange exchange, String msg) {
        ServerHttpResponse originalResponse = exchange.getResponse();
        originalResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
        originalResponse.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
        byte[] response = null;
        try {
            response = JSON.toJSONString(R.error(401, msg)).getBytes(Constants.UTF8);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        DataBuffer buffer = originalResponse.bufferFactory().wrap(response);
        return originalResponse.writeWith(Flux.just(buffer));
    }

    @Override
    public int getOrder() {
        return -200;
    }
}
