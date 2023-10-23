package mongoparser

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"go.keploy.io/server/pkg"
	"go.keploy.io/server/pkg/hooks"
	"go.keploy.io/server/pkg/models"
	"go.keploy.io/server/pkg/proxy/util"
	"go.keploy.io/server/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/x/mongo/driver/wiremessage"
	"go.uber.org/zap"
)

var Emoji = "\U0001F430" + " Keploy:"
var configRequests = []string{""}

// IsOutgoingMongo function determines if the outgoing network call is Mongo by comparing the
// message format with that of a mongo wire message.
func IsOutgoingMongo(buffer []byte) bool {
	if len(buffer) < 4 {
		return false
	}
	messageLength := binary.LittleEndian.Uint32(buffer[0:4])
	return int(messageLength) == len(buffer)
}

func ProcessOutgoingMongo(clientConnId, destConnId int64, requestBuffer []byte, clientConn, destConn net.Conn, h *hooks.Hook, started time.Time, readRequestDelay time.Duration, logger *zap.Logger, ctx context.Context) {
	switch models.GetMode() {
	case models.MODE_RECORD:
		logger.Debug("the outgoing mongo in record mode")
		encodeOutgoingMongo(clientConnId, destConnId, requestBuffer, clientConn, destConn, h, started, readRequestDelay, logger, ctx)
	case models.MODE_TEST:
		logger.Debug("the outgoing mongo in test mode")
		decodeOutgoingMongo(clientConnId, destConnId, requestBuffer, clientConn, destConn, h, started, readRequestDelay, logger)
	default:
	}
}

func decodeOutgoingMongo(clientConnId, destConnId int64, requestBuffer []byte, clientConn, destConn net.Conn, h *hooks.Hook, started time.Time, readRequestDelay time.Duration, logger *zap.Logger) {
	startedDecoding := time.Now()
	requestBuffers := [][]byte{requestBuffer}
	for {
		configMocks := h.GetConfigMocks()
		tcsMocks := h.GetTcsMocks()
		logger.Debug(fmt.Sprintf("the config mocks are: %v\nthe testcase mocks are: %v", configMocks, tcsMocks))

		var (
			mongoRequests = []models.MongoRequest{}
			err           error
		)
		if string(requestBuffer) == "read form client connection" {
			started := time.Now()
			conn := util.Connection{
				ClientConnection: &clientConn,
				DestConnection:   &destConn,
				IsClient:         true,
			}
			requestBuffer, err = util.ReadBytes(&conn)
			if err != nil {
				if err == io.EOF {
					logger.Debug("recieved request buffer is empty in test mode for mongo calls")
					return
				}
				logger.Error("failed to read request from the mongo client", zap.Error(err), zap.Any("clientConnId", clientConnId))
				return
			}
			requestBuffers = append(requestBuffers, requestBuffer)
			logger.Debug("the request from the mongo client", zap.Any("buffer", requestBuffer))
			readRequestDelay = time.Since(started)
		}
		if len(requestBuffer) == 0 {
			return
		}
		logger.Debug(fmt.Sprintf("the lopp starts for clientConnId: %v and the time delay: %v", clientConnId, time.Since(startedDecoding)))
		opReq, requestHeader, mongoRequest, err := Decode((requestBuffer), logger)
		if err != nil {
			logger.Error("failed to decode the mongo wire message from the client", zap.Error(err), zap.Any("clientConnId", clientConnId))
			return
		}
		mongoRequests = append(mongoRequests, models.MongoRequest{
			Header:    &requestHeader,
			Message:   mongoRequest,
			ReadDelay: int64(readRequestDelay),
		})
		if val, ok := mongoRequest.(*models.MongoOpMessage); ok && hasSecondSetBit(val.FlagBits) {
			for {
				started = time.Now()
				logger.Debug("into the for loop for request stream")
				conn := util.Connection{
					ClientConnection: &clientConn,
					DestConnection:   &destConn,
					IsClient:         true,
				}
				requestBuffer1, err := util.ReadBytes(&conn)
				if err != nil {
					if err == io.EOF {
						logger.Debug("recieved request buffer is empty for streaming mongo request call")
						return
					}
					logger.Error("failed to read reply from the mongo server", zap.Error(err), zap.String("mongo server address", destConn.RemoteAddr().String()))
					return
				}
				requestBuffers = append(requestBuffers, requestBuffer)
				readRequestDelay = time.Since(started)

				if len(requestBuffer1) == 0 {
					logger.Debug("the response from the server is complete")
					break
				}
				_, reqHeader, mongoReq, err := Decode(requestBuffer1, logger)
				if err != nil {
					logger.Error("failed to decode the mongo wire message from the mongo client", zap.Error(err), zap.Any("clientConnId", clientConnId))
					return
				}
				if mongoReqVal, ok := mongoReq.(models.MongoOpMessage); ok && !hasSecondSetBit(mongoReqVal.FlagBits) {
					logger.Debug("the request from the client is complete since the more_to_come flagbit is 0")
					break
				}
				mongoRequests = append(mongoRequests, models.MongoRequest{
					Header:    &reqHeader,
					Message:   mongoReq,
					ReadDelay: int64(readRequestDelay),
				})
			}
		}
		if isHeartBeat(opReq, *mongoRequests[0].Header, mongoRequests[0].Message) {
			logger.Debug("recieved a heartbeat request for mongo")
			maxMatchScore := 0.0
			bestMatchIndex := -1
			for configIndex, configMock := range configMocks {
				if len(configMock.Spec.MongoRequests) == len(mongoRequests) {
					for i, req := range configMock.Spec.MongoRequests {
						if len(configMock.Spec.MongoRequests) != len(mongoRequests) || req.Header.Opcode != mongoRequests[i].Header.Opcode {
							continue
						}
						switch req.Header.Opcode {
						case wiremessage.OpQuery:
							expectedQuery := req.Message.(*models.MongoOpQuery)
							actualQuery := mongoRequests[i].Message.(*models.MongoOpQuery)
							if actualQuery.FullCollectionName != expectedQuery.FullCollectionName ||
								actualQuery.ReturnFieldsSelector != expectedQuery.ReturnFieldsSelector ||
								actualQuery.Flags != expectedQuery.Flags ||
								actualQuery.NumberToReturn != expectedQuery.NumberToReturn ||
								actualQuery.NumberToSkip != expectedQuery.NumberToSkip {
								continue
							}

							expected := map[string]interface{}{}
							actual := map[string]interface{}{}
							err = bson.UnmarshalExtJSON([]byte(expectedQuery.Query), true, &expected)
							if err != nil {
								logger.Error(fmt.Sprintf("failed to unmarshal the section of recorded request to bson document"), zap.Error(err))
								continue
							}
							err = bson.UnmarshalExtJSON([]byte(actualQuery.Query), true, &actual)
							if err != nil {
								logger.Error(fmt.Sprintf("failed to unmarshal the section of incoming request to bson document"), zap.Error(err))
								continue
							}
							logger.Debug("the expected and actual msg in the single section.", zap.Any("expected", expected), zap.Any("actual", actual), zap.Any("score", calculateMatchingScore(expected, actual)))
							score := calculateMatchingScore(expected, actual)
							if score > maxMatchScore {
								maxMatchScore = score
								bestMatchIndex = configIndex
							}

						case wiremessage.OpMsg:
							if req.Message.(*models.MongoOpMessage).FlagBits != mongoRequests[i].Message.(*models.MongoOpMessage).FlagBits {
								continue
							}
							scoreSum := 0.0
							if len(req.Message.(*models.MongoOpMessage).Sections) != len(mongoRequests[i].Message.(*models.MongoOpMessage).Sections) {
								continue
							}
							for sectionIndx, section := range req.Message.(*models.MongoOpMessage).Sections {
								if len(req.Message.(*models.MongoOpMessage).Sections) == len(mongoRequests[i].Message.(*models.MongoOpMessage).Sections) {
									score := compareOpMsgSection(section, mongoRequests[i].Message.(*models.MongoOpMessage).Sections[sectionIndx], logger)
									scoreSum += score
								}
							}
							currentScore := scoreSum / float64(len(mongoRequests))
							if currentScore > maxMatchScore {
								maxMatchScore = currentScore
								bestMatchIndex = configIndex
							}
						default:
							logger.Error("the OpCode of the mongo wiremessage is invalid.")
						}
					}
				}
			}
			responseTo := mongoRequests[0].Header.RequestID
			if bestMatchIndex == -1 || maxMatchScore == 0.0 {
				logger.Debug("the mongo request do not matches with any config mocks", zap.Any("request", mongoRequests))
				continue
			}
			for _, mongoResponse := range configMocks[bestMatchIndex].Spec.MongoResponses {
				switch mongoResponse.Header.Opcode {
				case wiremessage.OpReply:
					replySpec := mongoResponse.Message.(*models.MongoOpReply)
					replyMessage, err := encodeOpReply(replySpec, logger)
					if err != nil {
						logger.Error(fmt.Sprintf("failed to encode the recorded OpReply yaml"), zap.Error(err), zap.Any("for request with id", responseTo))
						return
					}
					requestId := wiremessage.NextRequestID()
					heathCheckReplyBuffer := replyMessage.Encode(responseTo, requestId)
					responseTo = requestId
					logger.Debug(fmt.Sprintf("the bufffer response is: %v", string(heathCheckReplyBuffer)), zap.Any("clientconnid", clientConnId))
					_, err = clientConn.Write(heathCheckReplyBuffer)
					if err != nil {
						logger.Error("failed to write the health check reply to mongo client", zap.Error(err))
						return
					}
				case wiremessage.OpMsg:
					respMessage := mongoResponse.Message.(*models.MongoOpMessage)

					message, err := encodeOpMsg(respMessage, logger)
					if err != nil {
						logger.Error("failed to encode the recorded OpMsg response", zap.Error(err), zap.Any("for request with id", responseTo))
						return
					}
					if hasSecondSetBit(respMessage.FlagBits) {
						// the first response wiremessage have
						for {
							time.Sleep(time.Duration(mongoResponse.ReadDelay))
							// generate requestId for the mongo wiremessage
							requestId := wiremessage.NextRequestID()
							_, err := clientConn.Write(message.Encode(responseTo, requestId))
							logger.Debug(fmt.Sprintf("the response lifecycle ended. clientconnid: %v", clientConnId))
							if err != nil {
								logger.Error("failed to write the health check opmsg to mongo client", zap.Error(err))
								return
							}
							// the 'responseTo' field of response wiremessage is set to requestId of currently sent wiremessage
							responseTo = requestId
						}
					} else {

						_, err := clientConn.Write(message.Encode(responseTo, wiremessage.NextRequestID()))
						if err != nil {
							logger.Error("failed to write the health check opmsg to mongo client", zap.Error(err))
							return
						}
					}

				}
			}
		} else {
			maxMatchScore := 0.0
			bestMatchIndex := -1
			for tcsIndx, tcsMock := range tcsMocks {
				if len(tcsMock.Spec.MongoRequests) == len(mongoRequests) {
					for i, req := range tcsMock.Spec.MongoRequests {
						if len(tcsMock.Spec.MongoRequests) != len(mongoRequests) || req.Header.Opcode != mongoRequests[i].Header.Opcode {
							continue
						}
						switch req.Header.Opcode {
						case wiremessage.OpMsg:
							if req.Message.(*models.MongoOpMessage).FlagBits != mongoRequests[i].Message.(*models.MongoOpMessage).FlagBits {
								continue
							}
							scoreSum := 0.0
							for sectionIndx, section := range req.Message.(*models.MongoOpMessage).Sections {
								if len(req.Message.(*models.MongoOpMessage).Sections) == len(mongoRequests[i].Message.(*models.MongoOpMessage).Sections) {
									score := compareOpMsgSection(section, mongoRequests[i].Message.(*models.MongoOpMessage).Sections[sectionIndx], logger)
									scoreSum += score
								}
							}
							currentScore := scoreSum / float64(len(mongoRequests))
							if currentScore > maxMatchScore {
								maxMatchScore = currentScore
								bestMatchIndex = tcsIndx
							}
						default:
							logger.Error("the OpCode of the mongo wiremessage is invalid.")
						}
					}
				}
			}
			if bestMatchIndex == -1 {
				requestBuffer, err = util.Passthrough(clientConn, destConn, requestBuffers, h.Recover, logger)
				if err != nil {
					return
				}
				continue
			}

			responseTo := mongoRequests[0].Header.RequestID
			logger.Debug("the index mostly matched with the current request", zap.Any("indx", bestMatchIndex), zap.Any("responseTo", responseTo))
			if bestMatchIndex < 0 {
				logger.Debug(fmt.Sprintf("the bestMatchIndex before looping on MongoResponses is:%d", bestMatchIndex))
				continue
			}

			for _, resp := range tcsMocks[bestMatchIndex].Spec.MongoResponses {
				respMessage := resp.Message.(*models.MongoOpMessage)

				message, err := encodeOpMsg(respMessage, logger)
				if err != nil {
					logger.Error("failed to encode the recorded OpMsg response", zap.Error(err), zap.Any("for request with id", responseTo))
					return
				}
				requestId := wiremessage.NextRequestID()
				_, err = clientConn.Write(message.Encode(responseTo, requestId))
				if err != nil {
					logger.Error("failed to write the health check opmsg to mongo client", zap.Error(err), zap.Any("for request with id", responseTo))
					return
				}
				responseTo = requestId
			}
			logger.Debug(fmt.Sprintf("the length of tcsMocks before filtering matched: %v\n", len(tcsMocks)))
			if maxMatchScore > 0.0 && bestMatchIndex >= 0 && bestMatchIndex < len(tcsMocks) {
				tcsMocks = append(tcsMocks[:bestMatchIndex], tcsMocks[bestMatchIndex+1:]...)
				h.SetTcsMocks(tcsMocks)
			}
			logger.Debug(fmt.Sprintf("the length of tcsMocks after filtering matched: %v\n", len(tcsMocks)))
		}
		logger.Debug("the length of the requestBuffer after matching: " + strconv.Itoa(len(requestBuffer)) + strconv.Itoa(len(requestBuffers[0])))
		if len(requestBuffers) > 0 && len(requestBuffer) == len(requestBuffers[0]) {
			requestBuffer = []byte("read form client connection")
		}
		requestBuffers = [][]byte{}
	}
}

func encodeOutgoingMongo(clientConnId, destConnId int64, requestBuffer []byte, clientConn, destConn net.Conn, h *hooks.Hook, started time.Time, readRequestDelay time.Duration, logger *zap.Logger, ctx context.Context) {
	rand.Seed(time.Now().UnixNano())
	for {

		var err error
		var logStr string = fmt.Sprintln("the connection id: ", clientConnId, " the destination conn id: ", destConnId)

		logStr += fmt.Sprintln("started reading from the client: ", started)
		if string(requestBuffer) == "read form client connection" {
			lstr := ""
			started := time.Now()
			conn := util.Connection{
				ClientConnection: &clientConn,
				DestConnection:   &destConn,
				IsClient:         true,
			}
			requestBuffer, err = util.ReadBytes(&conn)
			logger.Debug("reading from the mongo connection", zap.Any("", string(requestBuffer)))
			if err != nil {
				if err == io.EOF {
					logger.Debug("recieved request buffer is empty in record mode for mongo call")
					return
				}
				logger.Error("failed to read request from the mongo client", zap.Error(err), zap.String("mongo client address", clientConn.RemoteAddr().String()), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
				return
			}
			readRequestDelay = time.Since(started)
			logStr += lstr
			logger.Debug(fmt.Sprintf("the request in the mongo parser before passing to dest: %v", len(requestBuffer)), zap.Any("client connId", clientConnId), zap.Any("dest connId", destConnId))
		}

		var (
			mongoRequests  = []models.MongoRequest{}
			mongoResponses = []models.MongoResponse{}
		)
		opReq, requestHeader, mongoRequest, err := Decode(requestBuffer, logger)
		if err != nil {
			logger.Error("failed to decode the mongo wire message from the client", zap.Error(err), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
			return
		}
		mongoRequests = append(mongoRequests, models.MongoRequest{
			Header:    &requestHeader,
			Message:   mongoRequest,
			ReadDelay: int64(readRequestDelay),
		})
		logStr += fmt.Sprintf("after reading request from client: %v\n", time.Since(started))
		_, err = destConn.Write(requestBuffer)
		if err != nil {
			logger.Error("failed to write the request buffer to mongo server", zap.Error(err), zap.String("mongo server address", destConn.RemoteAddr().String()), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
			return
		}
		logger.Debug(fmt.Sprintf("the request in the mongo parser after passing to dest: %v", len(requestBuffer)), zap.Any("client connId", clientConnId), zap.Any("dest connId", destConnId))

		logStr += fmt.Sprintln("after writing the request to the destination: ", time.Since(started))
		if val, ok := mongoRequest.(*models.MongoOpMessage); ok && hasSecondSetBit(val.FlagBits) {
			for {
				tmpStr := ""
				started = time.Now()
				conn := util.Connection{
					ClientConnection: &clientConn,
					DestConnection:   &destConn,
					IsClient:         true,
				}
				requestBuffer1, err := util.ReadBytes(&conn)
				logStr += tmpStr
				if err != nil {
					if err == io.EOF {
						logger.Debug("recieved request buffer is empty in record mode for mongo request")
						return
					}
					logger.Error("failed to read reply from the mongo server", zap.Error(err), zap.String("mongo server address", destConn.RemoteAddr().String()), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
					return
				}
				readRequestDelay = time.Since(started)

				logStr += fmt.Sprintf("after reading the response from destination: %v\n", time.Since(started))

				// write the reply to mongo client
				_, err = destConn.Write(requestBuffer1)
				if err != nil {
					// fmt.Println(logStr)
					logger.Error("failed to write the reply message to mongo client", zap.Error(err), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
					return
				}

				logStr += fmt.Sprintln("after writting response to the client: ", time.Since(started), "current time is: ", time.Now())

				if len(requestBuffer1) == 0 {
					logger.Debug("the response from the server is complete")
					break
				}
				_, reqHeader, mongoReq, err := Decode(requestBuffer1, logger)
				if err != nil {
					logger.Error("failed to decode the mongo wire message from the destination server", zap.Error(err), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
					return
				}
				if mongoReqVal, ok := mongoReq.(models.MongoOpMessage); ok && !hasSecondSetBit(mongoReqVal.FlagBits) {
					logger.Debug("the request from the client is complete since the more_to_come flagbit is 0")
					break
				}
				mongoRequests = append(mongoRequests, models.MongoRequest{
					Header:    &reqHeader,
					Message:   mongoReq,
					ReadDelay: int64(readRequestDelay),
				})

			}
		}

		// read reply message from the mongo server
		tmpStr := ""
		started = time.Now()
		conn := util.Connection{
			ClientConnection: &clientConn,
			DestConnection:   &destConn,
			IsClient:         false,
		}
		responseBuffer, err := util.ReadBytes(&conn)
		logger.Debug("reading from the destination mongo server", zap.Any("", string(responseBuffer)))
		logStr += tmpStr
		if err != nil {
			if err == io.EOF {
				logger.Debug("recieved response buffer is empty in record mode for mongo call")
				destConn.Close()
				return
			}
			logger.Error("failed to read reply from the mongo server", zap.Error(err), zap.String("mongo server address", destConn.RemoteAddr().String()), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
			return
		}
		readResponseDelay := time.Since(started)
		logStr += fmt.Sprintf("after reading the response from destination: %v\n", time.Since(started))

		// write the reply to mongo client
		_, err = clientConn.Write(responseBuffer)
		if err != nil {
			logger.Error("failed to write the reply message to mongo client", zap.Error(err), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
			return
		}

		logStr += fmt.Sprintln("after writting response to the client: ", time.Since(started), "current time is: ", time.Now())

		_, responseHeader, mongoResponse, err := Decode(responseBuffer, logger)
		if err != nil {
			logger.Error("failed to decode the mongo wire message from the destination server", zap.Error(err), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
			return
		}
		mongoResponses = append(mongoResponses, models.MongoResponse{
			Header:    &responseHeader,
			Message:   mongoResponse,
			ReadDelay: int64(readResponseDelay),
		})
		if val, ok := mongoResponse.(*models.MongoOpMessage); ok && hasSecondSetBit(val.FlagBits) {
			for i := 0; ; i++ {
				if i == 0 && isHeartBeat(opReq, *mongoRequests[0].Header, mongoRequests[0].Message) {
					go func() {
						// Recover from panic and gracefully shutdown
						defer h.Recover(pkg.GenerateRandomID())
						defer utils.HandlePanic()
						recordMessage(h, requestBuffer, responseBuffer, logStr, mongoRequests, mongoResponses, opReq, ctx)
					}()
				}
				tmpStr := ""
				started = time.Now()
				conn := util.Connection{
					ClientConnection: &clientConn,
					DestConnection:   &destConn,
					IsClient:         false,
				}
				responseBuffer, err = util.ReadBytes(&conn)
				logStr += tmpStr
				if err != nil {
					if err == io.EOF {
						logger.Debug("recieved response buffer is empty in record mode for mongo call")
						destConn.Close()
						return
					}
					logger.Error("failed to read reply from the mongo server", zap.Error(err), zap.String("mongo server address", destConn.RemoteAddr().String()), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
					return
				}
				logger.Debug(fmt.Sprintf("the response in the mongo parser before passing to client: %v", len(responseBuffer)), zap.Any("client connId", clientConnId), zap.Any("dest connId", destConnId))

				readResponseDelay := time.Since(started)

				logStr += fmt.Sprintf("after reading the response from destination: %v\n", time.Since(started))

				// write the reply to mongo client
				_, err = clientConn.Write(responseBuffer)
				if err != nil {
					// fmt.Println(logStr)
					logger.Error("failed to write the reply message to mongo client", zap.Error(err), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
					return
				}
				logger.Debug(fmt.Sprintf("the response in the mongo parser after passing to client: %v", len(responseBuffer)), zap.Any("client connId", clientConnId), zap.Any("dest connId", destConnId))

				logStr += fmt.Sprintln("after writting response to the client: ", time.Since(started), "current time is: ", time.Now())

				if len(responseBuffer) == 0 {
					logger.Debug("the response from the server is complete")
					break
				}

				_, respHeader, mongoResp, err := Decode(responseBuffer, logger)
				if err != nil {
					logger.Error("failed to decode the mongo wire message from the destination server", zap.Error(err), zap.Any("client conn id", clientConnId), zap.Any("dest conn id", destConnId))
					return
				}
				if mongoRespVal, ok := mongoResp.(models.MongoOpMessage); ok && !hasSecondSetBit(mongoRespVal.FlagBits) {
					logger.Debug("the response from the server is complete since the more_to_come flagbit is 0")
					break
				}
				mongoResponses = append(mongoResponses, models.MongoResponse{
					Header:    &respHeader,
					Message:   mongoResp,
					ReadDelay: int64(readResponseDelay),
				})
			}
		}

		go func() {
			// Recover from panic and gracefully shutdown
			defer h.Recover(pkg.GenerateRandomID())
			defer utils.HandlePanic()
			recordMessage(h, requestBuffer, responseBuffer, logStr, mongoRequests, mongoResponses, opReq, ctx)
		}()
		requestBuffer = []byte("read form client connection")

	}

}

func recordMessage(h *hooks.Hook, requestBuffer, responseBuffer []byte, logStr string, mongoRequests []models.MongoRequest, mongoResponses []models.MongoResponse, opReq Operation, ctx context.Context) {
	// // capture if the wiremessage is a mongo operation call

	shouldRecordCalls := true
	name := "mocks"
	meta1 := map[string]string{
		"operation": opReq.String(),
	}

	// Skip heartbeat from capturing in the global set of mocks. Since, the heartbeat packet always contain the "hello" boolean.
	// See: https://github.com/mongodb/mongo-go-driver/blob/8489898c64a2d8c2e2160006eb851a11a9db9e9d/x/mongo/driver/operation/hello.go#L503
	if isHeartBeat(opReq, *mongoRequests[0].Header, mongoRequests[0].Message) {
		meta1["type"] = "config"
		for _, v := range configRequests {
			// requestHeader.
			for _, req := range mongoRequests {

				switch req.Header.Opcode {
				case wiremessage.OpQuery:
					if req.Message.(*models.MongoOpQuery).Query == v {
						shouldRecordCalls = false
						break
					}
					configRequests = append(configRequests, req.Message.(*models.MongoOpQuery).Query)
				case wiremessage.OpMsg:
					if len(req.Message.(*models.MongoOpMessage).Sections) > 0 && req.Message.(*models.MongoOpMessage).Sections[0] == v {
						shouldRecordCalls = false
						break
					}
					configRequests = append(configRequests, req.Message.(*models.MongoOpMessage).Sections[0])
				default:
					if opReq.String() == v {
						shouldRecordCalls = false
						break
					}
					configRequests = append(configRequests, opReq.String())

				}
			}
		}
	}
	if shouldRecordCalls {
		mongoMock := &models.Mock{
			Version: models.V1Beta2,
			Kind:    models.Mongo,
			Name:    name,
			Spec: models.MockSpec{
				Metadata:       meta1,
				MongoRequests:  mongoRequests,
				MongoResponses: mongoResponses,
				Created:        time.Now().Unix(),
			},
		}
		h.AppendMocks(mongoMock, ctx)
	}
}

func hasSecondSetBit(num int) bool {
	// Shift the number right by 1 bit and check if the least significant bit is set
	return (num>>1)&1 == 1
}

func hasSixteenthBit(num int) bool {
	// Shift the number right by 1 bit and check if the least significant bit is set
	return (num>>16)&1 == 1
}

// Skip heartbeat from capturing in the global set of mocks. Since, the heartbeat packet always contain the "hello" boolean.
// See: https://github.com/mongodb/mongo-go-driver/blob/8489898c64a2d8c2e2160006eb851a11a9db9e9d/x/mongo/driver/operation/hello.go#L503
func isHeartBeat(opReq Operation, requestHeader models.MongoHeader, mongoRequest interface{}) bool {

	switch requestHeader.Opcode {
	case wiremessage.OpQuery:
		val, ok := mongoRequest.(*models.MongoOpQuery)
		if ok {
			return val.FullCollectionName == "admin.$cmd" && opReq.IsIsMaster() && strings.Contains(opReq.String(), "helloOk")
		}
	case wiremessage.OpMsg:
		_, ok := mongoRequest.(*models.MongoOpMessage)
		if ok {
			return opReq.IsIsAdminDB() && strings.Contains(opReq.String(), "hello")
		}
	default:
		return false
	}
	return false
}

func compareOpMsgSection(expectedSection, actualSection string, logger *zap.Logger) float64 {
	// check that the sections are of same type. SectionSingle (section[16] is "m") or SectionSequence (section[16] is "i").
	if (len(expectedSection) < 16 || len(actualSection) < 16) && expectedSection[16] != actualSection[16] {
		return 0
	}
	logger.Debug(fmt.Sprintf("the sections are. Expected: %v\n and actual: %v", expectedSection, actualSection))
	switch {
	case strings.HasPrefix(expectedSection, "{ SectionSingle identifier:"):
		var expectedIdentifier string
		var expectedMsgsStr string
		// // Define the regular expression pattern
		// // Compile the regular expression
		// // Find submatches using the regular expression

		expectedIdentifier, expectedMsgsStr, err := decodeOpMsgSectionSequence(expectedSection)
		if err != nil {
			logger.Debug(fmt.Sprintf("the section in mongo OpMsg wiremessage: %v", expectedSection))
			logger.Error("failed to fetch the identifier/msgs from the section sequence of recorded OpMsg", zap.Error(err), zap.Any("identifier", expectedIdentifier))
			return 0
		}

		var actualIdentifier string
		var actualMsgsStr string
		// _, err = fmt.Sscanf(actualSection, "{ SectionSingle identifier: %s , msgs: [ %s ] }", &actualIdentifier, &actualMsgsStr)
		actualIdentifier, actualMsgsStr, err = decodeOpMsgSectionSequence(actualSection)
		if err != nil {
			logger.Error("failed to fetch the identifier/msgs from the section sequence of incoming OpMsg", zap.Error(err), zap.Any("identifier", actualIdentifier))
			return 0
		}

		// // Compile the regular expression
		// // Find submatches using the regular expression

		logger.Debug("the expected section", zap.Any("identifier", expectedIdentifier), zap.Any("docs", expectedMsgsStr))
		logger.Debug("the actual section", zap.Any("identifier", actualIdentifier), zap.Any("docs", actualMsgsStr))

		expectedMsgs := strings.Split(expectedMsgsStr, ", ")
		actualMsgs := strings.Split(actualMsgsStr, ", ")
		if len(expectedMsgs) != len(actualMsgs) || expectedIdentifier != actualIdentifier {
			return 0
		}
		score := 0.0
		for i := range expectedMsgs {
			expected := map[string]interface{}{}
			actual := map[string]interface{}{}
			err := bson.UnmarshalExtJSON([]byte(expectedMsgs[i]), true, &expected)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to unmarshal the section of recorded request to bson document"), zap.Error(err))
				return 0
			}
			err = bson.UnmarshalExtJSON([]byte(actualMsgs[i]), true, &actual)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to unmarshal the section of incoming request to bson document"), zap.Error(err))
				return 0
			}
			score += calculateMatchingScore(expected, actual)
		}
		logger.Debug("the matching score for sectionSequence", zap.Any("", score))
		return score
	case strings.HasPrefix(expectedSection, "{ SectionSingle msg:"):
		var expectedMsgsStr string
		expectedMsgsStr, err := decodeOpMsgSectionSingle(actualSection)
		if err != nil {
			logger.Error("failed to fetch the msgs from the single section of recorded OpMsg", zap.Error(err))
			return 0
		}
		// // Define the regular expression pattern
		// // Compile the regular expression
		// // Find submatches using the regular expression

		var actualMsgsStr string
		actualMsgsStr, err = decodeOpMsgSectionSingle(actualSection)
		if err != nil {
			logger.Error("failed to fetch the msgs from the single section of incoming OpMsg", zap.Error(err))
			return 0
		}
		// // Compile the regular expression
		// // Find submatches using the regular expression

		expected := map[string]interface{}{}
		actual := map[string]interface{}{}

		err = bson.UnmarshalExtJSON([]byte(expectedMsgsStr), true, &expected)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to unmarshal the section of recorded request to bson document"), zap.Error(err))
			return 0
		}
		err = bson.UnmarshalExtJSON([]byte(actualMsgsStr), true, &actual)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to unmarshal the section of incoming request to bson document"), zap.Error(err))
			return 0
		}
		logger.Debug("the expected and actual msg in the single section.", zap.Any("expected", expected), zap.Any("actual", actual), zap.Any("score", calculateMatchingScore(expected, actual)))
		return calculateMatchingScore(expected, actual)

	default:
		logger.Error(fmt.Sprintf("failed to detect the OpMsg section into mongo request wiremessage due to invalid format"))
		return 0
	}
}

func calculateMatchingScore(obj1, obj2 map[string]interface{}) float64 {
	totalFields := len(obj2)
	matchingFields := 0.0

	for key, value := range obj2 {
		if obj1Value, ok := obj1[key]; ok {
			if reflect.DeepEqual(value, obj1Value) {
				matchingFields++
			} else if reflect.TypeOf(value) == reflect.TypeOf(obj1Value) {
				if isNestedMap(value) {
					if isNestedMap(obj1Value) {
						matchingFields += calculateMatchingScore(obj1Value.(map[string]interface{}), value.(map[string]interface{}))
					}
				} else if isSlice(value) {
					if isSlice(obj1Value) {
						matchingFields += calculateMatchingScoreForSlices(obj1Value.([]interface{}), value.([]interface{}))
					}
				}
			}
		}
	}

	return float64(matchingFields) / float64(totalFields)
}

func calculateMatchingScoreForSlices(slice1, slice2 []interface{}) float64 {
	matchingCount := 0

	if len(slice1) == len(slice2) {
		for indx2, item2 := range slice2 {
			if len(slice1) > indx2 && reflect.DeepEqual(item2, slice1[indx2]) {
				matchingCount++
			}
		}
	}

	return float64(matchingCount) / float64(len(slice2))
}

func isNestedMap(value interface{}) bool {
	_, ok := value.(map[string]interface{})
	return ok
}

func isSlice(value interface{}) bool {
	_, ok := value.([]interface{})
	return ok
}
