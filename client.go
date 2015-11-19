/*
PassCrackNet Client 0.0.1
By Adam "Akama" Ringwood
*/

package main

import (
        "net/http"
        "fmt"
        "os"
        "io/ioutil"
        "encoding/json"
        "strconv"
        "bytes"
        "os/exec"
        "time"
        "strings"
        "bufio"
        "code.google.com/p/gcfg"
)

const (
        BASE_URL = "http://10.21.5.116:8080/api/"
)

type Config struct {
        Settings struct {
                Location string
                Address string
                Rate string
        }
}

func main() {
        var cfg Config

        err := gcfg.ReadFileInto(&cfg, "settings.gcfg")
        if err != nil {
                panic(err)
        }


        var current_job *Job
        var current_task *Task

        for {
                start_main:




                current_job = getCurrentJob(cfg)

                if current_job.Id == 0 {
                        fmt.Println("Tried to fetch a job, but non-available or something is wrong with the server.")
                        time.Sleep(time.Second * 60)
                        goto start_main
                }

                fmt.Println("Received job: ", current_job)

                // debugging use only
                // fmt.Println("Hashed File: ", string(current_job.HashFile))

                time.Sleep(time.Millisecond * 1000)

                current_task = getCurrentTask(current_job, cfg)

                if current_task.Id == 0 {
                        fmt.Println("Tried to fetch a task, but non-available or something is wrong with the server.")
                        time.Sleep(time.Second * 60)
                        goto start_main
                }

                fmt.Println("Got task: ", current_task.Id)

                // Writing Hashfile
                writeHashFile(current_job)
                runHashcat(current_job, current_task, cfg)
                reportResults(current_job, current_task, cfg)

                // Clean Up Afterwards.
                cleanUp()
        }
}

func getCurrentJob(cfg Config) (j *Job) {
        var contents []byte
        response, err := http.Get(cfg.Settings.Address + "jobs/fetch")
        errorCheck(err)

        contents, err = ioutil.ReadAll(response.Body)
        errorCheck(err)

        j = &Job{}
        err = json.Unmarshal(contents, j)
        errorCheck(err)
        fmt.Println(j.Id)
        return
}

func getCurrentTask(j *Job, cfg Config) (t *Task) {
        var contents []byte

        jobId := strconv.Itoa(j.Id)

        url := cfg.Settings.Address + "jobs/" + jobId + "/fetch"
        fmt.Println(url)

        /*
        TODO: Automate rate setting.
        */
        var jsonStr = []byte(`{"task_rate":.cfg.Settings.Rate}`)

        req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
        req.Header.Set("Content-Type", "application/json")
        // NOTE this !!
        req.Close = true

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
                panic(err)
        }

        fmt.Println("REQ Sent")

        defer resp.Body.Close()

        // fmt.Println("response Status:", resp.Status)
        // fmt.Println("response Headers:", resp.Header)
        // body, _ := ioutil.ReadAll(resp.Body)
        // fmt.Println("response Body:", string(body))

        contents, err = ioutil.ReadAll(resp.Body)
        errorCheck(err)

        t = &Task{}
        err = json.Unmarshal(contents, t)
        errorCheck(err)
        fmt.Println(t)
        return
}

func writeHashFile(j *Job) {
        err := ioutil.WriteFile("input.txt", j.HashFile, 0644)
        errorCheck(err)
}

//command,"-a 3 -m 0", "output.txt", "?d?d?d?d?d?d"

func runHashcat(j *Job, t *Task, cfg Config) {
        command := "/home/isusec/oclHashcat-1.30/oclHashcat32.bin"


        AttackMode := strconv.Itoa(j.AttackMode)
        HashType := strconv.Itoa(j.HashType)
        Start := strconv.Itoa(t.Start)
        Finish := strconv.Itoa(t.Finish)

        //full_command := command + "-a " + AttackMode + "-m " + HashType + "-s " + Start + "-l " + Finish + "output.txt" + j.Mask

        fmt.Println(command + " -a " + AttackMode + " -m " + HashType + " -s " + Start  + " -l " + Finish + " input.txt " + j.Mask + " --force " + "-o " + "output.txt")

        out, err := exec.Command(command, "-a " + AttackMode, "-m " + HashType, "-s " + Start, "-l " + Finish, "input.txt", j.Mask, "--force",  "-o" + "output.txt").CombinedOutput()

        //out, err := exec.Command(full_command).CombinedOutput()

        if err != nil {
                fmt.Println(err)
        }

        output := string(out)

        fmt.Println("Output of file: ", output)
}

func reportResults(j *Job, t *Task, cfg Config) {
        if _, err := os.Stat("output.txt"); err == nil {
                fmt.Printf("A password was found for this task.")

                file, err := os.Open("output.txt")
                if err != nil {
                        panic(err)
                }
                defer file.Close()

                scanner := bufio.NewScanner(file)
                for scanner.Scan() {
                        cracked_password := strings.Split(scanner.Text(), ":")
                        if (len(cracked_password) == 3 || len(cracked_password) == 2) {
                                if (len(cracked_password) == 3) {
                                        sendResult(j.Id, t.Id, cracked_password[0], cracked_password[1], cracked_password[2], cfg)
                                } else {
                                        sendResult(j.Id, t.Id, cracked_password[0], "", cracked_password[1], cfg)
                                }
                        } else {
                                panic("Something is wrong with the output.txt file. Not formatted correctly.")
                        }
                }

                if err := scanner.Err(); err != nil {
                        panic(err)
                }
        } else {
                fmt.Println("No passwords were found for this task :(")
        }

        sendDone(j.Id, t.Id, cfg)
}

func sendResult(j_id int, t_id int, hash string, salt string, password string, cfg Config) {
        url := cfg.Settings.Address + "jobs/" + strconv.Itoa(j_id) + "/tasks/" + strconv.Itoa(t_id) + "/results"

        r := Result {
                Hash : hash,
                Salt : salt,
                Password : password,
        }

        jsonResult, err := json.Marshal(r)

        if err != nil {
                panic(err)
        }

        req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonResult))
        // NOTE this !!
        req.Close = true

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
                panic(err)
        }
        defer resp.Body.Close()
}

func sendDone(j_id int, t_id int, cfg Config) {
        url := cfg.Settings.Address + "jobs/" + strconv.Itoa(j_id) + "/tasks/" + strconv.Itoa(t_id) + "/done"

        req, err := http.NewRequest("POST", url, nil)
        // NOTE this !!
        req.Close = true

        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
                panic(err)
        }
        defer resp.Body.Close()

}

func cleanUp() {
        os.Remove("output.txt")
        os.Remove("oclHashcat.pot")
}

func errorCheck(e error) {
        if e != nil {
                fmt.Printf("%s\n", e)
                os.Exit(1)
        }

}

