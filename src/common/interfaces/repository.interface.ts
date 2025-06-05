export interface IBaseRepository<T> {
    findById(id: string): Promise<T | null>;
    findOne(where: any): Promise<T | null>;
    findMany(params: {
        where?: any;
        orderBy?: any;
        skip?: number;
        take?: number;
    }): Promise<T[]>;
    count(where?: any): Promise<number>;
    create(data: any): Promise<T>;
    update(id: string, data: any): Promise<T>;
    delete(id: string): Promise<T>;
    deleteMany(where: any): Promise<number>;
}
