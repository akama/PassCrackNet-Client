package main

type Job struct {
	Id         int       "_id" // uniq id for task
	AttackMode int       // 0 for dict, or 3 for hashmask.
	HashType   int       // type of hash.
	HashFile   []byte    // the file that contains hashes
	Mask       string    // mask or dict.
	Start      int       // start of number
	Finish     int       // Ending of string
	Tasks      []Task    // subset of tasks
	Results    []Result // sets of results
}

type Task struct {
	Id      int "_id"
	Start   int
	Finish  int
	Done    bool
}

type FetchJson struct {
	TaskRate string `json:"task_rate"`
}

type Result struct {
	Hash string
	Salt string
	Password string
}
